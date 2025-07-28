/**
@file pkt_capture.h
@author 남태일(taeil.nam@monitorapp.com)
@date 2025-07-20
@brief 패킷 캡처 관련 헤더파일
*/

#ifndef PKT_CAPTURE_H
#define PKT_CAPTURE_H

#include <pcap.h>

/*
********************************************************************************
* CONSTANTS
********************************************************************************
*/
#define MAX_PKT_CNTS 1000000 /**< 캡처 가능한 최대 패킷 개수 */
#define NET_IF_MAC 0x000c295de2b0ULL /**< 네트워크 인터페이스의 MAC 주소 */
#define NET_IF_IP 0xc0a8000a /**< 네트워크 인터페이스의 IP 주소 */
#define GATEWAY_MAC 0x005056e8707fULL /**< Gateway의 MAC 주소 */

/*
********************************************************************************
* DATATYPES
********************************************************************************
*/
typedef struct pkt {
	struct pcap_pkthdr *pkt_hdr;
	const u_char *pkt_data;

	uint16_t ip_offset;
	uint16_t tcp_offset;
	uint16_t tls_rec_offset;
	uint16_t tls_hand_offset;
	uint16_t tls_ch_offset;
	uint32_t tls_ext_offset;

	const char *tls_sni;
} pkt_t;

/*
********************************************************************************
* PROTOTYPES
********************************************************************************
*/
int pkt_capture_setup(void);
int pkt_capture(void);
void pkt_capture_free(void);

#endif

