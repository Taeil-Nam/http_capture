/**
@file pkt_capture.c
@author 남태일(taeil.nam@monitorapp.com)
@date 2025-07-17
@brief 패킷 캡처 관련 코드 
*/

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <syslog.h>
#include <netinet/in.h>
#include <pcap.h>
#include <time.h>
#include "cfg.h"
#include "log.h"
#include "pkt_capture.h"
#include "eth.h"
#include "ip.h"
#include "tcp.h"
#include "tls.h"

/*
********************************************************************************
* VARIABLES
********************************************************************************
*/
static pcap_t *pcap_handle; /**< pcap handle용 변수 */
static pcap_dumper_t *dumper; /**< 패킷 dump용 변수 */
static const char *net_if; /**< 패킷을 캡처할 네트워크 인터페이스 */
static int pkt_cnts; /**< 캡처할 패킷의 개수. 0 = 무제한 */
static int cur_pkt_cnts; /**< 캡처된 패킷의 개수 */
static const char *target_ip; /**< 캡처할 패킷의 IP 주소 */
static unsigned short target_port; /**< 캡처할 패킷의 Port 번호 */
static char err_buf[PCAP_ERRBUF_SIZE]; /**< PCAP 관련 에러 메시지 buffer */

/*
********************************************************************************
* PROTOTYPES
********************************************************************************
*/
static int pkt_inspect(pkt_t *pkt);
static void pkt_tcp_rst_send(pkt_t *pkt);
static void pkt_info_log(pkt_t *pkt);

/**
@brief pkt_capture_setup 함수

패킷 캡처 관련 초기 설정 로직 수행

@param void
@return int 성공시 0, pcap 설정 실패시 -1 반환
*/
int pkt_capture_setup(void)
{
	syslog(LOG_INFO, "Setting packet capture...[START]");

	/* 이전 pcap 설정 삭제 */
	pkt_capture_free();

	/* log 파일 생성 */
	log_file_open();

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
		dumper = pcap_dump_open(pcap_handle, CFG_DUMP_FILE_PATH);
		if (!dumper) {
			syslog(LOG_ERR, "%s", pcap_geterr(pcap_handle));
		} else {
			syslog(LOG_INFO, "Creating dump file...[DONE]");
		}
	}

	/* 패킷 카운트 설정 */
	pkt_cnts = atoi(cfg_val_find(CFG_PKT_CNTS));
	cur_pkt_cnts = 0;

	/* IP 필터링 설정 */
	target_ip = cfg_val_find(CFG_TARGET_IP);

	/* Port 필터링 설정 */
	target_port = atoi(cfg_val_find(CFG_TARGET_PORT));

	syslog(LOG_INFO, "Setting packet capture...[DONE]");

	return 0;
}

/**
@brief pkt_capture 함수

패킷 캡처 로직 수행

@param void
@return int 성공시 0 반환, 오류 또는 pkt_cnts 만큼 캡처된 경우 -1 반환.
*/
int pkt_capture(void)
{
	pkt_t pkt;
	int retval = 0;

	/* pkt_cnts 설정 값 만큼 패킷이 캡처된 경우 */
	if (pkt_cnts != 0 && cur_pkt_cnts >= pkt_cnts) {
		return -1;
	}

	memset(&pkt, 0, sizeof(pkt));

	/* 패킷 1개 캡처(Non-Blocking) */
	retval = pcap_next_ex(pcap_handle, &(pkt.pkt_hdr), &(pkt.pkt_data));

	/* 오류가 발생했거나(-1), 캡처된 패킷이 없는 경우(0) */
	if (retval == PCAP_ERROR) {
		LOG(ERR, "%s", pcap_geterr(pcap_handle));
		return -1;
	} else if (retval == 0) {
		return 0;
	}

	/* 필터에 맞는 패킷인지 검사 */
	if (pkt_inspect(&pkt) == -1) {
		return 0;
	}

	/* packet dump 생성 */
	if (cfg_dump_is_used()) {
		pcap_dump((u_char *)dumper, pkt.pkt_hdr, pkt.pkt_data);
	}

	/* packet log 생성 */
	pkt_info_log(&pkt);

	/* SNI로 rst 전송 */
	if (cfg_sni_rst_is_used() && pkt.tls_sni) {
		pkt_tcp_rst_send(&pkt);
	}

	/* SNI 메모리 반납 */
	if (pkt.tls_sni) {
		free((void *)pkt.tls_sni);
	}
	cur_pkt_cnts++;

	return 0;
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
@brief pkt_inspect 정적 함수

캡처된 패킷의 정보를 검사하여, 원하는 패킷인지 확인

@param pkt 캡처된 패킷
@return int 성공시 0 반환, 실패시 -1 반환
*/
static int pkt_inspect(pkt_t *pkt)
{
	eth_hdr_t *eth;
	uint8_t vlan_cnts;
	ip_hdr_t *ip;
	tcp_hdr_t *tcp;
	char src_ip_str[INET_ADDRSTRLEN];
	char dst_ip_str[INET_ADDRSTRLEN];

	/* Ethernet 파싱 */
	eth = eth_hdr_get(pkt->pkt_data);

	/* VLAN이 포함된 경우 */
	vlan_cnts = 0;
	while (eth->type == htons(ETH_P_8021Q)) {
		vlan_cnts++;
		eth = (eth_hdr_t *)((uint8_t *)eth + VLAN_LEN);
	}
	pkt->ip_offset = ETH_HDR_LEN + (VLAN_LEN * vlan_cnts);

	/* IP 파싱 */
	if (eth->type != htons(ETH_P_IP)) {
		return -1;
	}

	ip = ip_hdr_get(pkt->pkt_data + pkt->ip_offset);
	pkt->tcp_offset = pkt->ip_offset + ((ip->ver_ihl & 0x0F) * 4);
	if (!inet_ntop(AF_INET, &ip->src_ip, src_ip_str, INET_ADDRSTRLEN)) {
		LOG(ERR, "%s", strerror(errno));
		return -1;
	} else if (!inet_ntop(AF_INET, &ip->dst_ip, dst_ip_str, INET_ADDRSTRLEN)) {
		LOG(ERR, "%s", strerror(errno));
		return -1;
	}

	/* IP 필터링 */
	if (strcmp(src_ip_str, target_ip) != 0 &&
		strcmp(dst_ip_str, target_ip) != 0) {
		return -1;
	}

	/* TCP 파싱 */
	if (ip->protocol != IPPROTO_TCP) {
		return -1;
	}

	tcp = tcp_hdr_get(pkt->pkt_data + pkt->tcp_offset);
	if (ntohs(ip->tot_len) -
		((ip->ver_ihl & 0x0F) * 4) -
		((tcp->off_rsv >> 4) * 4) >= 5) {
		pkt->tls_rec_offset = pkt->tcp_offset + ((tcp->off_rsv >> 4) * 4);
	}

	/* Port 번호 필터링 */
	if (ntohs(tcp->src_port) != target_port &&
		ntohs(tcp->dst_port) != target_port) {
		return -1;
	}

	/* TLS와 HTTP만 수신 */
	if (ntohs(tcp->src_port) != 443 && ntohs(tcp->dst_port) != 443 &&
		ntohs(tcp->src_port) != 80 && ntohs(tcp->dst_port) != 80) {
		return -1;
	}

	/* SNI 추출 */
	tls_sni_get(pkt);

	return 0;
}

/**
@brief pkt_tcp_rst_send 정적 함수

tcp_rst 패킷을 주어진 SNI로 전송

@param pkt Client Hello 패킷
@return void
*/
static void pkt_tcp_rst_send(pkt_t *pkt)
{
	uint8_t send_pkt[60];
	eth_hdr_t *eth;
	ip_hdr_t *ip;
	ip_hdr_t *ip_prev;
	tcp_hdr_t *tcp;
	tcp_hdr_t *tcp_prev;
	int retval;
	pkt_t tcp_rst;

	memset(&send_pkt, 0, sizeof(send_pkt));
	ip_prev = (ip_hdr_t *)(pkt->pkt_data + pkt->ip_offset);
	tcp_prev = (tcp_hdr_t *)(pkt->pkt_data + pkt->tcp_offset);

	/* Ethernet 헤더 설정 */
	eth = (eth_hdr_t *)send_pkt;

	eth->dst_mac[0] = (GATEWAY_MAC >> 40) & 0xff;
	eth->dst_mac[1] = (GATEWAY_MAC >> 32) & 0xff;
	eth->dst_mac[2] = (GATEWAY_MAC >> 24) & 0xff;
	eth->dst_mac[3] = (GATEWAY_MAC >> 16) & 0xff;
	eth->dst_mac[4] = (GATEWAY_MAC >> 8) & 0xff;
	eth->dst_mac[5] = GATEWAY_MAC & 0xff;

	eth->src_mac[0] = (NET_IF_MAC >> 40) & 0xff;
	eth->src_mac[1] = (NET_IF_MAC >> 32) & 0xff;
	eth->src_mac[2] = (NET_IF_MAC >> 24) & 0xff;
	eth->src_mac[3] = (NET_IF_MAC >> 16) & 0xff;
	eth->src_mac[4] = (NET_IF_MAC >> 8) & 0xff;
	eth->src_mac[5] = NET_IF_MAC & 0xff;

	eth->type = htons(ETH_P_IP);

	/* IP 헤더 설정 */
	ip = (ip_hdr_t *)(send_pkt + sizeof(eth_hdr_t));

	ip->ver_ihl = 0x45;
	ip->tot_len = htons(0x0028);
	ip->frag_offset = htons(0x4000);
	ip->ttl = 64;
	ip->protocol = 6;
	ip->src_ip = htonl(NET_IF_IP);
	// TODO: dst ip(SNI's ip) 설정
	ip->dst_ip = ip_prev->dst_ip;
	ip->checksum = ip_checksum_cal((uint8_t *)ip, sizeof(ip_hdr_t));

	/* TCP 헤더 설정 */
	tcp = (tcp_hdr_t *)(send_pkt + sizeof(eth_hdr_t) + sizeof(ip_hdr_t));

	if (tcp_prev->src_port == htons(443)) {
		tcp->src_port = tcp_prev->dst_port;
	} else {
		tcp->src_port = tcp_prev->src_port;
	}
	tcp->dst_port = htons(443);
	tcp->seq_num = htonl(ntohl(tcp_prev->seq_num) +
			ntohs(ip_prev->tot_len) -
			sizeof(ip_hdr_t) -
			((tcp_prev->off_rsv >> 4) * 4));
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
		LOG(ERR, "Error send tcp_rst : %s", pcap_geterr(pcap_handle));
	} else if (retval == 0) {
		LOG(ERR, "Error send tcp_rst : sent packet size = 0");
	}

	/* 패킷 전송 log 생성 */
	LOG(INFO, "=====Sent TCP_rst packet=====");

	memset(&tcp_rst, 0, sizeof(pkt_t));
	tcp_rst.pkt_data = (const u_char *)(&send_pkt);
	tcp_rst.ip_offset = sizeof(eth_hdr_t);
	tcp_rst.tcp_offset = tcp_rst.ip_offset + sizeof(ip_hdr_t);
	pkt_info_log(&tcp_rst);
}

/**
@brief pkt_info_log 정적 함수

필터링된 패킷의 정보를 log 파일에 저장

@param pkt 캡처된 패킷
@return void
*/
static void pkt_info_log(pkt_t *pkt)
{
	eth_hdr_t *eth;
	ip_hdr_t *ip;
	char src_ip_str[INET_ADDRSTRLEN];
	char dst_ip_str[INET_ADDRSTRLEN];
	tcp_hdr_t *tcp;
	const char *flags = "CEUAPRSF";
	char tcp_flags[9];
	int flag_offset = 0x80;
	tls_rec_t *tls_rec;
	tls_hand_t *tls_hand;

	eth = eth_hdr_get(pkt->pkt_data);
	ip = ip_hdr_get(pkt->pkt_data + pkt->ip_offset);
	tcp = tcp_hdr_get(pkt->pkt_data + pkt->tcp_offset);
	if (!inet_ntop(AF_INET, &ip->src_ip, src_ip_str, INET_ADDRSTRLEN)) {
		LOG(ERR, "%s", strerror(errno));
		return;
	}
	if (!inet_ntop(AF_INET, &ip->dst_ip, dst_ip_str, INET_ADDRSTRLEN)) {
		LOG(ERR, "%s", strerror(errno));
		return;
	}

	LOG(INFO, "===PACKET INFO===[START]");

	/* Ethernet log */
	LOG(INFO, "[ETHERNET]");
	LOG(INFO,
		"src_mac = [%02x:%02x:%02x:%02x:%02x:%02x], "
		"dst_mac = [%02x:%02x:%02x:%02x:%02x:%02x], "
		"eth_type = [0x%04x], "
		"eth_size = [%d]",
		eth->src_mac[0], eth->src_mac[1], eth->src_mac[2],
		eth->src_mac[3], eth->src_mac[4], eth->src_mac[5],
		eth->dst_mac[0], eth->dst_mac[1], eth->dst_mac[2],
		eth->dst_mac[3], eth->dst_mac[4], eth->dst_mac[5],
		ntohs(eth->type),
		pkt->ip_offset);

	/* IP log */
	LOG(INFO, "[IP]");
	LOG(INFO, "src_ip = [%s], dst_ip = [%s], protocol = [%hu], ip_size = [%u]",
		src_ip_str,
		dst_ip_str,
		ip->protocol,
		(ip->ver_ihl & 0x0F) * 4);

	/* TCP log */
	LOG(INFO, "[TCP]");
	LOG(INFO, "src_port = [%hu], dst_port = [%hu], tcp_size = [%hu]",
		ntohs(tcp->src_port),
		ntohs(tcp->dst_port),
		(tcp->off_rsv >> 4) * 4);
	LOG(INFO, "seq_num = [%u], ack_num = [%u], data_len = [%u]",
		ntohl(tcp->seq_num),
		ntohl(tcp->ack_num),
		ntohs(ip->tot_len) - sizeof(ip_hdr_t) - ((tcp->off_rsv >> 4) * 4));

	for (int idx = 0; idx < 8; idx++) {
		if (tcp->flags & flag_offset) {
			tcp_flags[idx] = flags[idx];
		} else {
			tcp_flags[idx] = '.';
		}
		flag_offset = flag_offset >> 1;
	}
	tcp_flags[8] = '\0';
	LOG(INFO, "flags = [%s]", tcp_flags);

	/* TLS log */
	if (pkt->tls_rec_offset == 0) {
		LOG(INFO, "===PACKET INFO===[DONE]\n");
		return;
	}
	tls_rec = tls_rec_get(pkt->pkt_data + pkt->tls_rec_offset);

	LOG(INFO, "[TLS]");
	switch (tls_rec->type) {
	case TLS_CCS:
		LOG(INFO, "ChangeCipherSpec Message");
		break;
	case TLS_ALERT:
		LOG(INFO, "Alert Message");
		break;
	case TLS_HANDSHAKE:
		LOG(INFO, "Handshake Message");
		break;
	case TLS_APPLICATION:
		LOG(INFO, "Application Message");
		break;
	case TLS_HEARTBEAT:
		LOG(INFO, "Heartbeat Message");
		break;
	default:
		break;
	}

	if (tls_rec->type != TLS_HANDSHAKE) {
		LOG(INFO, "===PACKET INFO===[DONE]\n");
		return;
	}
	tls_hand = tls_hand_get(pkt->pkt_data + pkt->tls_hand_offset);
	
	switch (tls_hand->type) {
	case TLS_HANDSHAKE_CH:
		LOG(INFO, "Client Hello");
		break;
	case TLS_HANDSHAKE_SH:
		LOG(INFO, "Server Hello");
		break;
	case TLS_HANDSHAKE_NST:
		LOG(INFO, "New Session Ticket");
		break;
	case TLS_HANDSHAKE_EE:
		LOG(INFO, "Encrypted Extensions");
		break;
	case TLS_HANDSHAKE_CERT:
		LOG(INFO, "Certificate");
		break;
	case TLS_HANDSHAKE_SKE:
		LOG(INFO, "Server Key Exchange");
		break;
	case TLS_HANDSHAKE_CR:
		LOG(INFO, "Certificate Request");
		break;
	case TLS_HANDSHAKE_SHD:
		LOG(INFO, "Server Hello Done");
		break;
	case TLS_HANDSHAKE_CV:
		LOG(INFO, "Certificate Verify");
		break;
	case TLS_HANDSHAKE_CKE:
		LOG(INFO, "Client Key Exchange");
		break;
	case TLS_HANDSHAKE_FIN:
		LOG(INFO, "Finished");
		break;
	default:
		break;
	}

	if (tls_hand->type != TLS_HANDSHAKE_CH) {
		LOG(INFO, "===PACKET INFO===[DONE]\n");
		return;
	}
	if (pkt->tls_sni) {
		LOG(INFO, "SNI = [%s]", pkt->tls_sni);
	}

	LOG(INFO, "===PACKET INFO===[DONE]\n");
}

