/**
@file pkt_capture.c
@author 남태일(taeil.nam@monitorapp.com)
@date 2025-07-17
@brief 패킷 캡처 관련 코드 
*/

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <netinet/in.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <syslog.h>
#include <time.h>
#include "cfg.h"
#include "log.h"
#include "pkt_capture.h"
#include "eth.h"
#include "ip.h"
#include "tcp.h"
#include "tls.h"
#include "http.h"

/*
********************************************************************************
* VARIABLES
********************************************************************************
*/
static pcap_t *pcap_handle;
static pcap_dumper_t *dumper;
static const char *net_if;
static int pkt_cnts;
static int cur_pkt_cnts;
static const char *target_ip;
static const char *target_port_str;
bool pkt_port_filter_list[MAX_PORT_NUM + 1];
static char err_buf[PCAP_ERRBUF_SIZE];

/*
********************************************************************************
* PROTOTYPES
********************************************************************************
*/
static void pkt_target_port_apply(void);
static int pkt_inspect(pkt_t *pkt);
static void pkt_tcp_rst_send(pkt_t *pkt);
static void pkt_info_log(pkt_t *pkt);

/**
@brief pkt_capture_setup 함수

패킷 캡처 관련 초기 설정 로직 수행

@param void
@return 성공시 0, 실패시 -1 반환
*/
int pkt_capture_setup(void)
{
	syslog(LOG_INFO, "Setting packet capture...[START]");
	pkt_capture_free();
	/* log 파일 생성 */
	log_file_open();
	/* 패킷 카운트 설정 */
	pkt_cnts = atoi(cfg_val_find(CFG_PKT_CNTS));
	cur_pkt_cnts = 0;
	/* 패킷 필터링 설정 */
	target_ip = cfg_val_find(CFG_TARGET_IP);
	pkt_target_port_apply();
	/* pcap_t 생성 */
	net_if = cfg_val_find(CFG_NET_IF_NAME);
	pcap_handle = pcap_create(net_if, err_buf);
	if (!pcap_handle) {
		syslog(LOG_ERR, "%s", err_buf);
		return -1;
	}
	/* pcap_t 설정 */
	if (pcap_set_immediate_mode(pcap_handle, 1) != 0) {
		syslog(LOG_ERR, "Can't set immediate mode to pcap.");
		return -1;
	} else if (pcap_setnonblock(pcap_handle, 1, err_buf) != 0) {
		syslog(LOG_ERR, "%s", pcap_geterr(pcap_handle));
		return -1;
	}
	/* pcap_t 활성화 */
	if (pcap_activate(pcap_handle) < 0) {
		syslog(LOG_ERR, "%s", pcap_geterr(pcap_handle));
		pcap_close(pcap_handle);
		pcap_handle = NULL;
		return -1;
	}
	/* dump 파일 생성 */
	if (cfg_dump_is_used()) {
		syslog(LOG_INFO, "Creating dump file...[START]");
		dumper = pcap_dump_open_append(pcap_handle, CFG_DUMP_FILE_PATH);
		if (!dumper) {
			syslog(LOG_ERR, "%s", pcap_geterr(pcap_handle));
		} else {
			syslog(LOG_INFO, "Creating dump file...[DONE]");
		}
	}
	syslog(LOG_INFO, "Setting packet capture...[DONE]");
	return 0;
}

/**
@brief pkt_capture 함수

패킷 캡처 로직 수행

@param void
@return 성공시 0 반환, 오류 발생 또는 pkt_cnts 만큼 캡처된 경우 -1 반환
*/
int pkt_capture(void)
{
	pkt_t pkt;
	int retval = 0;

	if (pkt_cnts != 0 && cur_pkt_cnts >= pkt_cnts) {
		return -1;
	}
	memset(&pkt, 0, sizeof(pkt));
	/* 패킷 1개 캡처(Non-Blocking) */
	retval = pcap_next_ex(pcap_handle, &(pkt.pkt_hdr), &(pkt.pkt_data));
	if (retval == PCAP_ERROR) {
		LOG(ERR, "%s", pcap_geterr(pcap_handle));
		return -1;
	} else if (retval == 0) {
		return 0;
	}
	/* 패킷 파싱 및 검사 */
	if (pkt_inspect(&pkt) == -1) {
		return 0;
	}
	/* 패킷 dump 생성 */
	if (cfg_dump_is_used()) {
		pcap_dump((u_char *)dumper, pkt.pkt_hdr, pkt.pkt_data);
	}
	/* 패킷 log 생성 */
	pkt_info_log(&pkt);
	/* tls client hello 패킷인 경우, sni로 rst 패킷 전송 */
	if (cfg_sni_rst_is_used() && pkt.tls_sni) {
		pkt_tcp_rst_send(&pkt);
	}
	/* sni 메모리 반납 */
	if (pkt.tls_sni) {
		free((void *)pkt.tls_sni);
	}
	cur_pkt_cnts++;
	return 0;
}
/**
@brief pkt_port_is_filtered 함수

전달 받은 port 번호가 필터링 목록에 포함되는지 여부를 반환

@param void
@return bool 포함되는 경우 true, 미포함인 경우 false 반환
*/
bool pkt_port_is_filtered(uint16_t port)
{
	return pkt_port_filter_list[port];
}


/**
@brief pkt_capture_free 함수

패킷 캡처 관련 자원 반납

@param void
@return void
*/
void pkt_capture_free(void)
{
	if (pcap_handle) {
		pcap_close(pcap_handle);
		pcap_handle = NULL;
	}
	if (dumper) {
		pcap_dump_close(dumper);
		dumper = NULL;
	}
	log_file_close();
}

/**
@brief pkt_target_port_apply 정적 함수

port 번호 목록을 파싱 후 필터링 적용

@param void
@return void
*/
void pkt_target_port_apply(void)
{
	int target_port_str_len = 0;
	int start = 0;
	int end = 0;
	int idx = 0;
	int port_number = 0;
	bool flag = false;

	target_port_str = cfg_val_find(CFG_TARGET_PORT);
	target_port_str_len = (int)strlen(target_port_str);
	memset(pkt_port_filter_list, 0, sizeof(pkt_port_filter_list));
	while (end < target_port_str_len) {
		const char *port_str = NULL;
		flag = false;

		/* 콤마(',')를 기준으로 각 port 번호 파싱 */
		while (target_port_str[end] != ',' && end < target_port_str_len) {
			end++;
		}
		/* 값이 없는 경우 생략 */
		if (end - start == 0) {
			end++;
			start = end;
			continue;
		}
		/* start ~ end까지의 문자열 저장 */
		port_str = strndup(&target_port_str[start], end - start);
		if (port_str == NULL) {
			syslog(LOG_ERR, "strndup returns NULL in pkt_target_port_apply()");
			end++;
			start = end;
			continue;
		}
		/* 자리 수가 5를 초과하는 경우 생략 */
		if (end - start > 5) {
			syslog(LOG_WARNING, "Target port [%s] is invalid. "
				"Program will ignore this port number during capture.",
				port_str);
			free((void *)port_str);
			end++;
			start = end;
			continue;
		}
		/* 숫자가 아닌 값이 포함되어 있으면 생략 */
		idx = 0;
		while (idx < end - start) {
			if (!isdigit(port_str[idx])) {
				syslog(LOG_WARNING, "Target port [%s] is invalid. "
					"Program will ignore this port number during capture.",
					port_str);
				flag = true;
				break;
			}
			idx++;
		}
		if (flag) {
			free((void *)port_str);
			end++;
			start = end;
			continue;
		}
		/* port number = 0 ~ 65535가 아닌 경우 생략 */
		port_number = atoi(port_str);
		if (port_number < 0 || port_number > MAX_PORT_NUM) {
			syslog(LOG_WARNING, "Target port [%s] is invalid. "
				"Program will ignore this port number during capture.",
				port_str);
			free((void *)port_str);
			end++;
			start = end;
			continue;
		}
		/* port filter 목록에 추가 */
		pkt_port_filter_list[port_number] = true;
		free((void *)port_str);
		end++;
		start = end;
	}
}

/**
@brief pkt_inspect 정적 함수

캡처된 패킷의 정보를 파싱 및 검사하여, 원하는 패킷인지 확인

@param pkt 캡처된 패킷
@return 성공시 0 반환, 실패시 -1 반환
*/
static int pkt_inspect(pkt_t *pkt)
{
	eth_hdr_t *eth;
	uint8_t vlan_cnts;
	ip_hdr_t *ip;
	tcp_hdr_t *tcp;
	char src_ip_str[INET_ADDRSTRLEN];
	char dst_ip_str[INET_ADDRSTRLEN];

	/* ethernet 파싱 */
	eth = eth_hdr_get(pkt);
	/* vlan이 포함된 경우 */
	vlan_cnts = 0;
	while (eth->type == htons(ETH_P_8021Q)) {
		vlan_cnts++;
		eth = (eth_hdr_t *)((uint8_t *)eth + VLAN_LEN);
	}
	pkt->ip_offset = ETH_HDR_LEN + (VLAN_LEN * vlan_cnts);
	/* ip 파싱 */
	if (eth->type != htons(ETH_P_IP)) {
		return -1;
	}
	ip = ip_hdr_get(pkt);
	pkt->tcp_offset = pkt->ip_offset + ((ip->ver_ihl & 0x0F) * 4);
	if (!inet_ntop(AF_INET, &ip->src_ip, src_ip_str, INET_ADDRSTRLEN)) {
		LOG(ERR, "%s", strerror(errno));
		return -1;
	} else if (!inet_ntop(AF_INET, &ip->dst_ip, dst_ip_str, INET_ADDRSTRLEN)) {
		LOG(ERR, "%s", strerror(errno));
		return -1;
	}
	/* tcp 파싱 */
	if (ip->protocol != IPPROTO_TCP) {
		return -1;
	}
	tcp = tcp_hdr_get(pkt);
	pkt->tcp_data_offset = pkt->tcp_offset + tcp_hdr_len_get(pkt);
	/* ip 필터링 */
	if (strcmp(src_ip_str, target_ip) != 0 &&
		strcmp(dst_ip_str, target_ip) != 0) {
		return -1;
	}
	/* port 번호 필터링 */
	if (!pkt_port_is_filtered(ntohs(tcp->src_port)) &&
		!pkt_port_is_filtered(ntohs(tcp->dst_port))) {
		return -1;
	}
	/* tls client hello 메시지인 경우 sni 추출 */
	if (ntohs(tcp->dst_port) == 443) {
		tls_sni_get(pkt);
	}
	return 0;
}

/**
@brief pkt_tcp_rst_send 정적 함수

주어진 tls client hello 패킷에 대한 tcp rst 패킷 전송

@param pkt tls client hello 패킷
@return void
*/
static void pkt_tcp_rst_send(pkt_t *pkt)
{
	uint8_t send_pkt[60];
	eth_hdr_t *eth;
	eth_hdr_t *eth_prev;
	ip_hdr_t *ip;
	ip_hdr_t *ip_prev;
	tcp_hdr_t *tcp;
	tcp_hdr_t *tcp_prev;
	int retval;
	pkt_t tcp_rst;

	memset(&send_pkt, 0, sizeof(send_pkt));
	eth_prev = (eth_hdr_t *)(pkt->pkt_data);
	ip_prev = (ip_hdr_t *)(pkt->pkt_data + pkt->ip_offset);
	tcp_prev = (tcp_hdr_t *)(pkt->pkt_data + pkt->tcp_offset);

	/* ethernet 헤더 설정 */
	eth = (eth_hdr_t *)send_pkt;
	memcpy(eth->dst_mac, eth_prev->dst_mac, MAC_LEN);
	memcpy(eth->src_mac, eth_prev->src_mac, MAC_LEN);
	eth->type = htons(ETH_P_IP);
	/* ip 헤더 설정 */
	ip = (ip_hdr_t *)(send_pkt + sizeof(eth_hdr_t));
	ip->ver_ihl = 0x45;
	ip->tot_len = htons(0x0028);
	ip->frag_offset = htons(0x4000);
	ip->ttl = 64;
	ip->protocol = IPPROTO_TCP;
	ip->src_ip = ip_prev->src_ip;
	ip->dst_ip = ip_prev->dst_ip;
	ip->checksum = ip_checksum_cal((uint8_t *)ip, sizeof(ip_hdr_t));
	/* tcp 헤더 설정 */
	tcp = (tcp_hdr_t *)(send_pkt + sizeof(eth_hdr_t) + sizeof(ip_hdr_t));
	if (tcp_prev->src_port == htons(443)) {
		tcp->src_port = tcp_prev->dst_port;
	} else {
		tcp->src_port = tcp_prev->src_port;
	}
	tcp->dst_port = htons(443);
	tcp->seq_num = htonl(ntohl(tcp_prev->seq_num) + tcp_data_len_get(pkt));
	tcp->ack_num = 0;
	tcp->off_rsv = 0x50;
	tcp->flags = 0x04;
	tcp->window = 0;
	tcp->urg_ptr = 0;
	tcp->checksum = tcp_checksum_cal((uint8_t *)ip, (uint8_t *)tcp,
			ntohs(ip->tot_len) - sizeof(ip_hdr_t));
	/* 패킷 전송 */
	retval = pcap_inject(pcap_handle, send_pkt, sizeof(send_pkt));
	if (retval == PCAP_ERROR) {
		LOG(ERR, "Error sending tcp_rst : %s", pcap_geterr(pcap_handle));
		return;
	} else if (retval == 0) {
		LOG(ERR, "Error sending tcp_rst : sent packet size = 0");
		return;
	}
	/* 패킷 전송 dump 생성 */
	pcap_dump((u_char *)dumper, pkt->pkt_hdr, send_pkt);
	/* 패킷 전송 log 출력 */
	LOG(INFO, "=====SENT TCP RST PACKET=====[START]");
	memset(&tcp_rst, 0, sizeof(pkt_t));
	tcp_rst.pkt_data = (const u_char *)(&send_pkt);
	tcp_rst.ip_offset = sizeof(eth_hdr_t);
	tcp_rst.tcp_offset = tcp_rst.ip_offset + sizeof(ip_hdr_t);
	pkt_info_log(&tcp_rst);
	/* 패킷 캡처 카운트 증가 */
	cur_pkt_cnts++;
}

/**
@brief pkt_info_log 정적 함수

필터링된 패킷의 정보를 log로 출력

@param pkt 캡처된 패킷
@return void
*/
static void pkt_info_log(pkt_t *pkt)
{
	LOG(INFO, "===PACKET INFO===[START]");
	eth_log(pkt);
	ip_log(pkt);
	tcp_log(pkt);
	http_log(pkt);
	tls_log(pkt);
	LOG(INFO, "===PACKET INFO===[DONE]\n");
}

