/**
@file ip.c
@author 남태일(taeil.nam@monitorapp.com)
@date 2025-07-23
@brief IP 로직 관련 코드 
*/

#include "ip.h"

/**
@brief ip_hdr_get 함수

주어진 패킷에서 IP 헤더 반환

@param pkt_data 패킷 데이터
@return ip_hdr_t * ip_hdr_t 구조체 포인터 반환
*/
ip_hdr_t *ip_hdr_get(const uint8_t *pkt_data)
{
	return (ip_hdr_t *)pkt_data;
}

