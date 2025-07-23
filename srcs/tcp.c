/**
@file tcp.c
@author 남태일(taeil.nam@monitorapp.com)
@date 2025-07-23
@brief TCP 로직 관련 코드 
*/

#include "tcp.h"

/**
@brief tcp_hdr_get 함수

주어진 패킷에서 TCP 헤더 반환

@param pkt_data 패킷 데이터
@return tcp_hdr_t * tcp_hdr_t 구조체 포인터 반환
*/
tcp_hdr_t *tcp_hdr_get(const uint8_t *pkt_data)
{
	return (tcp_hdr_t *)pkt_data;
}

