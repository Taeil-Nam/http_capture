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
#include "tls.h"

/*
********************************************************************************
* DATA TYPES
********************************************************************************
*/

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
static int pkt_inspect(struct pcap_pkthdr *pkt_hdr, const u_char *pkt_data);

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
	struct pcap_pkthdr *pkt_hdr;
	const u_char *pkt_data;
	int retval = 0;
	int cnts = 0;

	/* pkt_cnts 만큼 패킷 캡처된 경우 */
	if (cnts >= pkt_cnts) {
		return -1;
	}

	retval = pcap_next_ex(pcap_handle, &pkt_hdr, &pkt_data);

	/* 오류 발생시 */
	if (retval == PCAP_ERROR) {
		LOG(ERR, "%s", pcap_geterr(pcap_handle));
		return -1;
	}

	/* 설정에 맞는 패킷인지 검사 */
	// TODO: pkt_inspect 여러 개의 함수로 쪼개기
	if (pkt_inspect(pkt_hdr, pkt_data) == -1)
		return 0;

	// pkt_inspect() 검사 이후 부분 아래에 작성
	cnts++;

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

@param void
@return int 성공시 0 반환, 실패시 1 반환
*/
static int pkt_inspect(struct pcap_pkthdr *pkt_hdr, const u_char *pkt_data)
{
	struct eth_hdr *eth;
	struct ip_hdr *ip;
	struct tcp_hdr *tcp;
	int eth_size = 0;
	int ip_size = 0;
	int tcp_size = 0;
	char src_ip_str[INET_ADDRSTRLEN];
	char dst_ip_str[INET_ADDRSTRLEN];

	/* ethernet parsing test */
	eth = (struct eth_hdr *)pkt_data;
	eth_size = sizeof(struct eth_hdr);
	/*
	LOG(INFO,
		"src_mac = [%02x:%02x:%02x:%02x:%02x:%02x], "
		"dst_mac = [%02x:%02x:%02x:%02x:%02x:%02x], "
		"eth_size = %d",
		eth->dst_mac[0], eth->dst_mac[1], eth->dst_mac[2],
		eth->dst_mac[3], eth->dst_mac[4], eth->dst_mac[5],
		eth->src_mac[0], eth->src_mac[1], eth->src_mac[2],
		eth->src_mac[3], eth->src_mac[4], eth->src_mac[5],
		eth_size);
	*/
	if (eth->type != htons(ETH_P_IP))
		return -1;

	/* ip parsing test */
	ip = (struct ip_hdr *)(pkt_data + eth_size);
	unsigned char ihl = ip->ver_ihl & 0x0F;
	ip_size = (ihl * 4);
	inet_ntop(AF_INET, &ip->src_ip, src_ip_str, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &ip->dst_ip, dst_ip_str, INET_ADDRSTRLEN);

	/* ip 필터링 */
	if (strcmp(src_ip_str, target_ip) != 0 &&
		strcmp(dst_ip_str, target_ip) != 0)
		return -1;
	/*
	LOG(INFO,
		"src_ip = [%s], dst_ip = [%s], protocol = [%hu], ip_size = [%d]",
		src_ip_str,
		dst_ip_str,
		ip->protocol,
		ip_size);
	*/
	if (ip->protocol != IPPROTO_TCP)
		return -1;

	/* tcp parsing test */
	tcp = (struct tcp_hdr *)(pkt_data + eth_size + ip_size);

	/* port 필터링 */
	if (ntohs(tcp->src_port) != target_port &&
		ntohs(tcp->dst_port) != target_port)
		return -1;

	unsigned char offset = tcp->off_rsv >> 4;
	/*
	LOG(INFO,
		"src_port = [%hu], dst_port = [%hu], seq_num = [%u], ack_num = [%u], data_offset = [%hu]",
		ntohs(tcp->src_port),
		ntohs(tcp->dst_port),
		ntohl(tcp->seq_num),
		ntohl(tcp->ack_num), offset * 4);
	*/
	tcp_size = offset * 4;

	/* TLS parsing test */
	/* 필터링 거친 패킷이므로, 덤프에 저장 및 패킷 카운트 증가 */
	/* dump 생성 */
	if (cfg_dump_is_used()) {
		pcap_dump((u_char *)dumper, pkt_hdr, pkt_data);
	}

	struct tls_rec *tls;
	tls = (struct tls_rec *)(pkt_data + eth_size + ip_size + tcp_size);

	/* tls handshake msg */
	if (tls->type != 0x16)
		return -1;

	struct tls_hand *tls_hand = (struct tls_hand *)((uint8_t *)tls + sizeof(struct tls_rec));

	/* tls client hello msg */
	if (tls_hand->type != 0x01)
		return -1;

	/* SNI 찾기 */
	uint8_t *client_hello = (uint8_t *)((uint8_t *)tls_hand + sizeof(struct tls_hand));
	unsigned int ch_len = 0;
	ch_len = (tls_hand->len[0] << 16) | (tls_hand->len[1] << 8) | tls_hand->len[0];
	const char *tls_sni = tls_sni_get(client_hello, ch_len);
	LOG(INFO, "===PACKET INFO===[START]");
	LOG(INFO, "This is TLS Client Hello Message");
	LOG(INFO,
		"src_mac = [%02x:%02x:%02x:%02x:%02x:%02x], "
		"dst_mac = [%02x:%02x:%02x:%02x:%02x:%02x], "
		"eth_size = %d",
		eth->dst_mac[0], eth->dst_mac[1], eth->dst_mac[2],
		eth->dst_mac[3], eth->dst_mac[4], eth->dst_mac[5],
		eth->src_mac[0], eth->src_mac[1], eth->src_mac[2],
		eth->src_mac[3], eth->src_mac[4], eth->src_mac[5],
		eth_size);

	LOG(INFO,
		"src_ip = [%s], dst_ip = [%s], protocol = [%hu], ip_size = [%d]",
		src_ip_str,
		dst_ip_str,
		ip->protocol,
		ip_size);

	LOG(INFO,
		"src_port = [%hu], dst_port = [%hu], seq_num = [%u], ack_num = [%u], data_offset = [%hu]",
		ntohs(tcp->src_port),
		ntohs(tcp->dst_port),
		ntohl(tcp->seq_num),
		ntohl(tcp->ack_num), offset * 4);

	LOG(INFO,
		"TLS_SNI = [%s]",
		tls_sni);

	/* TODO: sni로 rst 패킷 전송 */

	free((void *)tls_sni); // free test code
	LOG(INFO, "===PACKET INFO===[DONE]");

	return 0;
}

