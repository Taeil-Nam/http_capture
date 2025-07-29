/**
@file tcp.h
@author 남태일(taeil.nam@monitorapp.com)
@date 2025-07-23
@brief TCP 로직 관련 헤더 파일
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
#define PSEUDO_HDR_LEN 12 /**< Pseudo Header 길이(bytes) */

/*
********************************************************************************
* DATA TYPES
********************************************************************************
*/
typedef struct __attribute__((packed)) tcp_hdr {
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq_num;
	uint32_t ack_num;
	uint8_t off_rsv;
	uint8_t flags;
	uint16_t window;
	uint16_t checksum;
	uint16_t urg_ptr;
} tcp_hdr_t;

/*
********************************************************************************
* PROTOTYPES
********************************************************************************
*/
tcp_hdr_t *tcp_hdr_get(pkt_t *pkt);
uint8_t tcp_hdr_len_get(pkt_t *pkt);
uint16_t tcp_checksum_cal(uint8_t *ip_hdr, uint8_t *tcp, int tcp_len);
void tcp_log(pkt_t *pkt);

#endif

