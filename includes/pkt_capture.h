/**
@file pkt_capture.h
@author 남태일(taeil.nam@monitorapp.com).
@date 2025-07-20.
@brief 패킷 캡처 관련 헤더파일.
*/

#ifndef PKT_CAPTURE_H
#define PKT_CAPTURE_H

#include <pcap.h>
#include <stdbool.h>

/*
********************************************************************************
* CONSTANTS
********************************************************************************
*/
#define MAX_PKT_CNTS 1000000 /**< 캡처 가능한 최대 패킷 개수 */

/*
********************************************************************************
* DATATYPES
********************************************************************************
*/
/**
@brief 캡처된 패킷의 정보를 가지고 있는 구조체.
*/
typedef struct pkt {
	struct pcap_pkthdr *pkt_hdr; /**< pcap으로 캡처된 패킷의 정보 */
	const u_char *pkt_data; /**< pcap으로 캡처된 패킷의 실제 데이터 */

	uint16_t ip_offset; /**< pkt_data에서 ip header가 시작되는 지점 */
	uint16_t tcp_offset; /**< pkt_data에서 tcp header가 시작되는 지점 */
	uint16_t tcp_data_offset; /**< pkt_data에서 tcp data가 시작되는 지점 */

	const char *tls_sni; /**< tls client hello의 sni */
} pkt_t;

/*
********************************************************************************
* PROTOTYPES
********************************************************************************
*/
int pkt_capture_setup(void);
int pkt_capture(void);
bool pkt_port_is_filtered(uint16_t port);
void pkt_capture_free(void);

#endif

