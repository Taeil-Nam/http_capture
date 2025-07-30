/**
@file eth.h
@author 남태일(taeil.nam@monitorapp.com)
@date 2025-07-23
@brief ethernet 로직 관련 헤더 파일
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
#define ETH_HDR_LEN 14 /**< ethernet 헤더 길이(byte) */
#define VLAN_LEN 4 /**< vlan tag 길이(byte) */
#define MAC_LEN 6 /**< mac 주소 길이(byte) */

/*
********************************************************************************
* DATA TYPES
********************************************************************************
*/
/**
@brief ethernet 헤더를 나타내는 구조체
*/
typedef struct __attribute__((packed)) eth_hdr {
	uint8_t dst_mac[MAC_LEN]; /**< destination mac */
	uint8_t src_mac[MAC_LEN]; /**< source mac */
	uint16_t type; /** ethertype */
} eth_hdr_t;

/*
********************************************************************************
* PROTOTYPES
********************************************************************************
*/
eth_hdr_t *eth_hdr_get(pkt_t *pkt);
void eth_log(pkt_t *pkt);

#endif

