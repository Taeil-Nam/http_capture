/**
@file pkt_capture.c
@author 남태일(taeil.nam@monitorapp.com)
@date 2025-07-17
@brief 패킷 캡처 관련 코드 
*/

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pcap.h>
#include <time.h>
#include "cfg.h"
#include "log.h"
#include "pkt_capture.h"

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
pcap_t *pcap_handle; /**< 패킷 캡처 로직 handle용 변수 */
pcap_dumper_t *dumper; /**< 패킷 dump용 변수 */
static const char *net_if; /**< 패킷을 캡처할 네트워크 인터페이스 */
static char err_buf[PCAP_ERRBUF_SIZE]; /**< PCAP 관련 에러 메시지 buffer */

/*
********************************************************************************
* PROTOTYPES
********************************************************************************
*/
static void pkt_inspect(struct pcap_pkthdr *pkt_hdr, const u_char *pkt_data);

/**
@brief pkt_capture_setup 함수

패킷 캡처 관련 초기 설정 로직 수행

@param void
@return void
*/
void pkt_capture_setup(void)
{
	LOG(INFO, "Setting packet capture...[START]");

	/* 이전 pcap 설정 삭제 */
	pkt_capture_free();

	/* log 파일 생성 */
	log_file_open();

	/* pcap_t 생성 */
	net_if = cfg_val_find(CFG_NET_IF_NAME);
	pcap_handle = pcap_create(net_if, err_buf);
	if (!pcap_handle) {
		LOG(ERR, "%s", err_buf);
		return;
	}

	/* pcap_t 설정 */
	if (pcap_set_immediate_mode(pcap_handle, 1) != 0) {
		LOG(ERR, "Can't set immediate mode to pcap.");
		return;
	} else if (pcap_setnonblock(pcap_handle, 1, err_buf) != 0) {
		LOG(ERR, "%s", pcap_geterr(pcap_handle));
		return;
	}

	/* pcap_t 활성화 */
	if (pcap_activate(pcap_handle) < 0) {
		LOG(ERR, "%s", pcap_geterr(pcap_handle));
		pcap_close(pcap_handle);
		pcap_handle = NULL;
		return;
	}

	/* dump 파일 생성 */
	if (cfg_dump_is_used()) {
		dumper = pcap_dump_open_append(pcap_handle, CFG_DUMP_FILE_PATH);
		if (!dumper) {
			LOG(ERR, "%s", pcap_geterr(pcap_handle));
		}
	}

	LOG(INFO, "Setting packet capture...[DONE]");
}

/**
@brief pkt_capture 함수

패킷 캡처 로직 수행

@param void
@return void
*/
void pkt_capture(void)
{
	struct pcap_pkthdr *pkt_hdr;
	const u_char *pkt_data;
	int retval = 0;

	LOG(INFO, "===PACKET INFO===[START]");

	retval = pcap_next_ex(pcap_handle, &pkt_hdr, &pkt_data);
	//TODO:  패킷 캡처시(1), 오류 발생시(PCAP_ERROR) 로직 추가 필요
	if (retval == PCAP_ERROR) {
		LOG(ERR, "%s", pcap_geterr(pcap_handle));
		return;
	} else if (retval == 1) {
		// TODO: tls 패킷인지 검사 후, SNI 저장 및 rst 패킷 전송
		pkt_inspect(pkt_hdr, pkt_data);
	}

	LOG(INFO, "===PACKET INFO===[DONE]");
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
@return void
*/
static void pkt_inspect(struct pcap_pkthdr *pkt_hdr, const u_char *pkt_data)
{
	struct eth_hdr *eth;
	struct ip_hdr *ip;
	struct tcp_hdr *tcp;
	int eth_size = 0;
	int ip_size = 0;
	int tcp_size = 0;
	struct in_addr src_ip;
	struct in_addr dst_ip;

	/* ethernet parsing test */
	eth = (struct eth_hdr *)pkt_data;
	LOG(INFO,
		"src_mac = [%02x:%02x:%02x:%02x:%02x:%02x], "
		"dst_mac = [%02x:%02x:%02x:%02x:%02x:%02x]",
		eth->dst_mac[0], eth->dst_mac[1], eth->dst_mac[2],
		eth->dst_mac[3], eth->dst_mac[4], eth->dst_mac[5],
		eth->src_mac[0], eth->src_mac[1], eth->src_mac[2],
		eth->src_mac[3], eth->src_mac[4], eth->src_mac[5]);
	eth_size = sizeof(struct eth_hdr);

	if (eth->type != htons(ETH_P_IP))
		return;

	/* ip parsing test */
	ip = (struct ip_hdr *)(pkt_data + eth_size);
	src_ip.s_addr = ip->src_ip;
	dst_ip.s_addr = ip->dst_ip;
	LOG(INFO,
		"src_ip = [%s], dst_ip = [%s], protocol = [%hu]",
		inet_ntoa(src_ip),
		inet_ntoa(dst_ip),
		ip->protocol);
	ip_size = eth_size + (ip->ihl * 4);

	if (ip->protocol != IPPROTO_TCP)
		return;

	/* tcp parsing test */
	tcp = (struct tcp_hdr *)(pkt_data + eth_size + ip_size);
	LOG(INFO,
		"src_port = [%hu], dst_port = [%hu], seq_num = [%u], ack_num = [%u], data_offset = [%hu]",
		tcp->src_port, tcp->dst_port, tcp->seq_num, tcp->ack_num, tcp->data_offset);
	tcp_size = eth_size + ip_size + (tcp->data_offset * 4);

	// TODO: TLS 패킷 검사
	(void)tcp_size;
	(void)pkt_hdr;
}

