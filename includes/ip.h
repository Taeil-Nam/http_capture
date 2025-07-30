/**
@file ip.h
@author 남태일(taeil.nam@monitorapp.com)
@date 2025-07-23
@brief ip 로직 관련 헤더 파일
*/

#ifndef IP_H
#define IP_H

#include <stdint.h>
#include "pkt_capture.h"

/*
********************************************************************************
* DATA TYPES
********************************************************************************
*/
/**
@brief ip 헤더를 나타내는 구조체
*/
typedef struct  __attribute__((packed)) ip_hdr {
	uint8_t ver_ihl; /**< version(4), ihl(4) */
	uint8_t tos; /**< dscp(6), ecn(2) */
	uint16_t tot_len; /**< total length */
	uint16_t id; /**< identification */
	uint16_t frag_offset; /**< flags(3), fragment offset(13) */
	uint8_t ttl; /**< time to live */
	uint8_t protocol; /**< protocol */
	uint16_t checksum; /**< checksum */
	uint32_t src_ip; /**< source ip */
	uint32_t dst_ip; /**< destination ip */
} ip_hdr_t;

/*
********************************************************************************
* PROTOTYPES
********************************************************************************
*/
ip_hdr_t *ip_hdr_get(pkt_t *pkt);
uint8_t ip_hdr_len_get(pkt_t *pkt);
uint16_t ip_tot_len_get(pkt_t *pkt);
uint16_t ip_checksum_cal(uint8_t *ip_hdr, int hdr_len);
void ip_log(pkt_t *pkt);

#endif

