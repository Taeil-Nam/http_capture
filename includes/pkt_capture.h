/**
@file pkt_capture.h
@author 남태일(taeil.nam@monitorapp.com)
@date 2025-07-20
@brief 패킷 캡처 관련 헤더파일
*/

#ifndef PKT_CAPTURE_H
#define PKT_CAPTURE_H

/*
********************************************************************************
* CONSTANTS
********************************************************************************
*/
#define MAX_PKT_CNTS 1000000000 /**< 캡처 가능한 최대 패킷 개수 */
#define PCAP_ERR_INTERVAL 10 /**< 오류 발생시 재설정 간격(초) */
#define MAC_LEN 6 /**< MAC 주소 길이(byte) */

/*
********************************************************************************
* DATA TYPES
********************************************************************************
*/
struct eth_hdr {
	unsigned char dst_mac[MAC_LEN];
	unsigned char src_mac[MAC_LEN];
	unsigned short type;
} __attribute__((packed));

struct ip_hdr {
	unsigned char version:4,
				  ihl:4;
	unsigned char tos;
	unsigned short tot_len;
	unsigned short id;
	unsigned short frag_offset;
	unsigned char ttl;
	unsigned char protocol;
	unsigned short checksum;
	unsigned int src_ip;
	unsigned int dst_ip;
} __attribute__((packed));

struct tcp_hdr {
	unsigned short src_port;
	unsigned short dst_port;
	unsigned int seq_num;
	unsigned int ack_num;
	unsigned short data_offset:4,
				   reserved:4,
				   cwr:1,
				   ece:1,
				   urg:1,
				   ack:1,
				   psh:1,
				   rst:1,
				   syn:1,
				   fin:1;
	unsigned short window;
	unsigned short checksum;
	unsigned short urg_ptr;
} __attribute__((packed));

/*
********************************************************************************
* PROTOTYPES
********************************************************************************
*/
void pkt_capture_setup(void);
void pkt_capture(void);
void pkt_capture_free(void);

#endif

