/**
@file eth.c
@author 남태일(taeil.nam@monitorapp.com)
@date 2025-07-23
@brief Ethernet 로직 관련 코드 
*/

#include "eth.h"

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

