/**
@file ip.h
@author 남태일(taeil.nam@monitorapp.com)
@date 2025-07-23
@brief IP 로직 관련 헤더 파일
*/

#ifndef IP_H
#define IP_H

#include <stdint.h>

/*
********************************************************************************
* DATA TYPES
********************************************************************************
*/
typedef struct  __attribute__((packed)) ip_hdr {
	uint8_t ver_ihl;
	uint8_t tos;
	uint16_t tot_len;
	uint16_t id;
	uint16_t frag_offset;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;
	uint32_t src_ip;
	uint32_t dst_ip;
} ip_hdr_t;

/*
********************************************************************************
* PROTOTYPES
********************************************************************************
*/
ip_hdr_t *ip_hdr_get(const uint8_t *pkt_data);

#endif

