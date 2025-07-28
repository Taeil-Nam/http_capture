/**
@file ip.c
@author 남태일(taeil.nam@monitorapp.com)
@date 2025-07-23
@brief IP 로직 관련 코드 
*/

#include <arpa/inet.h>
#include "ip.h"

/**
@brief ip_hdr_get 함수

주어진 패킷에서 IP 헤더 반환

@param pkt pkt_t 구조체
@return ip_hdr_t * ip_hdr_t 구조체 포인터 반환
*/
ip_hdr_t *ip_hdr_get(pkt_t *pkt)
{
	return (ip_hdr_t *)(pkt->pkt_data + pkt->ip_offset);
}

/**
@brief ip_checksum_cal 함수

IP Checksum 값 계산 후 반환

@param ip_hdr 계산에 사용될 ip 헤더
@param hdr_len ip 헤더의 크기
@return uint16_t 계산된 Checksum 값
*/
uint16_t ip_checksum_cal(uint8_t *ip_hdr, int hdr_len)
{
	uint16_t *data = (uint16_t *)ip_hdr;
	uint32_t checksum = 0;

	while (hdr_len > 1) {
		checksum += ntohs(*data);
		data++;
		hdr_len -= 2;
	}
	if (hdr_len == 1) {
		checksum += *((uint8_t *)data);
	}

    checksum = (checksum >> 16) + (checksum & 0xFFFF);
    checksum += (checksum >> 16);

    return htons((uint16_t)(~checksum));
}

