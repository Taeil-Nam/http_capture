/**
@file tcp.h
@author 남태일(taeil.nam@monitorapp.com)
@date 2025-07-23
@brief tcp 로직 관련 헤더 파일
*/

#ifndef TCP_H
#define TCP_H

#include <stdint.h>
#include "pkt_capture.h"

/*
********************************************************************************
* CONSTANTS
********************************************************************************
*/
#define PSEUDO_HDR_LEN 12 /**< pseudo header 길이(bytes) */

/*
********************************************************************************
* DATA TYPES
********************************************************************************
*/
/**
@brief tcp 헤더를 나타내는 구조체
*/
typedef struct __attribute__((packed)) tcp_hdr {
	uint16_t src_port; /**< source port */
	uint16_t dst_port; /**< destination port */
	uint32_t seq_num; /**< sequence number */
	uint32_t ack_num; /**< acknowledgement number */
	uint8_t off_rsv; /**< data offset(4), reserved(4) */
	uint8_t flags; /**< flags */
	uint16_t window; /** window */
	uint16_t checksum; /** checksum */
	uint16_t urg_ptr; /** urgent pointer */
} tcp_hdr_t;

/*
********************************************************************************
* PROTOTYPES
********************************************************************************
*/
tcp_hdr_t *tcp_hdr_get(pkt_t *pkt);
uint8_t tcp_hdr_len_get(pkt_t *pkt);
uint16_t tcp_data_len_get(pkt_t *pkt);
uint16_t tcp_checksum_cal(uint8_t *ip_hdr, uint8_t *tcp, int tcp_len);
void tcp_log(pkt_t *pkt);

#endif

