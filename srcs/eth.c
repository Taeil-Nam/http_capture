/**
@file eth.c
@author 남태일(taeil.nam@monitorapp.com)
@date 2025-07-23
@brief Ethernet 로직 관련 코드 
*/

#include "eth.h"
#include "log.h"

/**
@brief eth_hdr_get 함수

주어진 패킷에서 Ethernet 헤더 반환

@param pkt pkt_t 구조체
@return eth_hdr_t * eth_hdr_t 구조체 포인터 반환
*/
eth_hdr_t *eth_hdr_get(pkt_t *pkt)
{
	return (eth_hdr_t *)pkt->pkt_data;
}

/**
@brief eth_log 함수

주어진 패킷에서 Ethernet 정보 로깅

@param pkt pkt_t 구조체
@return void
*/
void eth_log(pkt_t *pkt)
{
	eth_hdr_t *eth;

	eth = eth_hdr_get(pkt);
	LOG(INFO, "[ETHERNET]");
	LOG(INFO,
	"src_mac = [%02x:%02x:%02x:%02x:%02x:%02x], "
	"dst_mac = [%02x:%02x:%02x:%02x:%02x:%02x], "
	"eth_type = [0x%04x], eth_size = [%d]",
	eth->src_mac[0], eth->src_mac[1], eth->src_mac[2],
	eth->src_mac[3], eth->src_mac[4], eth->src_mac[5],
	eth->dst_mac[0], eth->dst_mac[1], eth->dst_mac[2],
	eth->dst_mac[3], eth->dst_mac[4], eth->dst_mac[5],
	ntohs(eth->type), pkt->ip_offset);
}

