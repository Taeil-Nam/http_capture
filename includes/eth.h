/**
@file eth.h
@author 남태일(taeil.nam@monitorapp.com)
@date 2025-07-23
@brief Ethernet 로직 관련 헤더 파일
*/

#ifndef ETH_H
#define ETH_H

#include <stdint.h>
#include "pkt_capture.h"

/*
********************************************************************************
* CONSTANTS
********************************************************************************
*/
#define ETH_HDR_LEN 14 /**< Ethernet 헤더 길이(byte) */
#define VLAN_LEN 4 /**< VLAN Tag 길이(byte) */
#define MAC_LEN 6 /**< MAC 주소 길이(byte) */

/*
********************************************************************************
* DATA TYPES
********************************************************************************
*/
typedef struct __attribute__((packed)) eth_hdr {
	uint8_t dst_mac[MAC_LEN];
	uint8_t src_mac[MAC_LEN];
	uint16_t type;
} eth_hdr_t;

/*
********************************************************************************
* PROTOTYPES
********************************************************************************
*/
eth_hdr_t *eth_hdr_get(pkt_t *pkt);
void eth_log(pkt_t *pkt);

#endif

