/**
@file pkt_capture.c
@author 남태일(taeil.nam@monitorapp.com)
@date 2025-07-17
@brief 패킷 캡처 관련 코드 
*/

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
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
static pcap_t *pcap_handle; /**< 패킷 캡처 로직 handle용 변수 */
static pcap_dumper_t *dumper; /**< 패킷 dump용 변수 */
static const char *net_if; /**< 패킷을 캡처할 네트워크 인터페이스 */
static int pkt_cnts; /**< 캡처할 패킷의 개수. 0 = 무제한 */
static const char *target_ip; /**< 캡처할 패킷의 IP 주소 */
static unsigned short target_port; /**< 캡처할 패킷의 Port 번호 */
static char err_buf[PCAP_ERRBUF_SIZE]; /**< PCAP 관련 에러 메시지 buffer */

/*
********************************************************************************
* PROTOTYPES
********************************************************************************
*/
static int pkt_inspect(pkt_t *pkt);
static void pkt_info_log(pkt_t *pkt);

/**
@brief pkt_capture_setup 함수

패킷 캡처 관련 초기 설정 로직 수행

@param void
@return void
*/
void pkt_capture_setup(void)
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
		return;
	}

	/* pcap_t 설정 */
	if (pcap_set_immediate_mode(pcap_handle, 1) != 0) {
		syslog(LOG_ERR, "Can't set immediate mode to pcap.");
		return;
	} else if (pcap_setnonblock(pcap_handle, 1, err_buf) != 0) {
		syslog(LOG_ERR, "%s", pcap_geterr(pcap_handle));
		return;
	}

	/* pcap_t 활성화 */
	if (pcap_activate(pcap_handle) < 0) {
		syslog(LOG_ERR, "%s", pcap_geterr(pcap_handle));
		pcap_close(pcap_handle);
		pcap_handle = NULL;
		return;
	}

	/* dump 파일 생성 */
	if (cfg_dump_is_used()) {
		dumper = pcap_dump_open(pcap_handle, CFG_DUMP_FILE_PATH);
		if (!dumper) {
			syslog(LOG_ERR, "%s", pcap_geterr(pcap_handle));
		}
	}

	/* 패킷 카운트 설정 */
	pkt_cnts = atoi(cfg_val_find(CFG_PKT_CNTS));

	/* IP 필터링 설정 */
	target_ip = cfg_val_find(CFG_TARGET_IP);

	/* Port 필터링 설정 */
	target_port = atoi(cfg_val_find(CFG_TARGET_PORT));

	syslog(LOG_INFO, "Setting packet capture...[DONE]");
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
	int pcap_cnts = 0;

	/* pkt_cnts 설정 값 만큼 패킷 캡처된 경우 */
	if (pkt_cnts != 0 && pcap_cnts >= pkt_cnts) {
		return -1;
	}

	/* 패킷 1개 캡처 */
	retval = pcap_next_ex(pcap_handle, &(pkt.pkt_hdr), &(pkt.pkt_data));

	/* 오류 발생시 */
	if (retval == PCAP_ERROR) {
		LOG(ERR, "%s", pcap_geterr(pcap_handle));
		return -1;
	}

	/* 필터에 맞는 패킷인지 검사 */
	if (pkt_inspect(&pkt) == -1) {
		//LOG(INFO, "This captured packet is not a target packet");
		return 0;
	}

	/* packet에 대한 dump 생성 */
	if (cfg_dump_is_used()) {
		pcap_dump((u_char *)dumper, pkt.pkt_hdr, pkt.pkt_data);
	}

	/* SNI 찾기 */
	pkt.tls_sni = tls_sni_get(&pkt);

	/* 패킷 정보 로깅 */
	pkt_info_log(&pkt);

	/* SNI로 rst 전송 */
	if (cfg_sni_rst_is_used()) {
		// TODO: SNI로 rst 전송
	}

	if (pkt.tls_sni) {
		free((void *)pkt.tls_sni);
	}
	pcap_cnts++;

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

	/* VLAN 포함된 경우 */
	vlan_cnts = 0;
	while (eth->type == ETH_P_8021Q) {
		vlan_cnts++;
		eth = (eth_hdr_t *)((uint8_t *)eth + VLAN_LEN);
	}
	pkt->ip_offset = ETH_HDR_LEN + (VLAN_LEN * vlan_cnts);

	/* IP 파싱 */
	ip = ip_hdr_get(pkt->pkt_data + pkt->ip_offset);
	pkt->tcp_offset = pkt->ip_offset + ((ip->ver_ihl & 0x0F) * 4);
	inet_ntop(AF_INET, &ip->src_ip, src_ip_str, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &ip->dst_ip, dst_ip_str, INET_ADDRSTRLEN);

	/* IP 필터링 */
	if (strcmp(src_ip_str, target_ip) != 0 &&
		strcmp(dst_ip_str, target_ip) != 0) {
		return -1;
	}
	if (ip->protocol != IPPROTO_TCP) {
		return -1;
	}

	/* TCP 파싱 */
	tcp = tcp_hdr_get(pkt->pkt_data + pkt->tcp_offset);
	pkt->tls_rec_offset = pkt->tcp_offset + ((tcp->off_rsv >> 4) * 4);

	/* Port 번호 필터링 */
	// TODO: TLS, HTTP만 수신되어야 하는지?
	// 일단 config의 port로 필터링 중
	if (ntohs(tcp->src_port) != target_port &&
		ntohs(tcp->dst_port) != target_port) {
		return -1;
	}

	// pkt_info_log()

	return 0;
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
	tcp_hdr_t *tcp;
	char src_ip_str[INET_ADDRSTRLEN];
	char dst_ip_str[INET_ADDRSTRLEN];

	eth = eth_hdr_get(pkt->pkt_data);
	ip = ip_hdr_get(pkt->pkt_data + pkt->ip_offset);
	tcp = tcp_hdr_get(pkt->pkt_data + pkt->tcp_offset);
	inet_ntop(AF_INET, &ip->src_ip, src_ip_str, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &ip->dst_ip, dst_ip_str, INET_ADDRSTRLEN);

	LOG(INFO, "===PACKET INFO===[START]");
	LOG(INFO,
		"src_mac = [%02x:%02x:%02x:%02x:%02x:%02x], "
		"dst_mac = [%02x:%02x:%02x:%02x:%02x:%02x], "
		"eth_size = [%d]",
		eth->src_mac[0], eth->src_mac[1], eth->src_mac[2],
		eth->src_mac[3], eth->src_mac[4], eth->src_mac[5],
		eth->dst_mac[0], eth->dst_mac[1], eth->dst_mac[2],
		eth->dst_mac[3], eth->dst_mac[4], eth->dst_mac[5],
		pkt->ip_offset);

	LOG(INFO,
		"src_ip = [%s], dst_ip = [%s], protocol = [%hu], ip_size = [%d]",
		src_ip_str,
		dst_ip_str,
		ip->protocol,
		(ip->ver_ihl & 0x0F) * 4);

	LOG(INFO,
		"src_port = [%hu], dst_port = [%hu], "
		"seq_num = [%u], ack_num = [%u], data_offset = [%hu]",
		ntohs(tcp->src_port),
		ntohs(tcp->dst_port),
		ntohl(tcp->seq_num),
		ntohl(tcp->ack_num),
		(tcp->off_rsv >> 4) * 4);

	// TODO: TLS 정보 추가
	if (pkt->tls_sni) {
		LOG(INFO,
			"!!!!! TLS_SNI = [%s] !!!!!",
			pkt->tls_sni);
	}

	LOG(INFO, "===PACKET INFO===[DONE]\n");
}

