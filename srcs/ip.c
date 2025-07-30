/**
@file ip.c
@author 남태일(taeil.nam@monitorapp.com)
@date 2025-07-23
@brief ip 로직 관련 코드
*/

#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include "ip.h"
#include "log.h"

/**
@brief ip_hdr_get 함수

주어진 패킷의 ip 헤더 반환

@param pkt pkt_t 구조체
@return ip_hdr_t 구조체 포인터 반환
*/
ip_hdr_t *ip_hdr_get(pkt_t *pkt)
{
	return (ip_hdr_t *)(pkt->pkt_data + pkt->ip_offset);
}

/**
@brief ip_hdr_len_get 함수

주어진 패킷의 ip 헤더 길이 반환

@param pkt pkt_t 구조체
@return ip 헤더의 길이
*/
uint8_t ip_hdr_len_get(pkt_t *pkt)
{
	ip_hdr_t *ip;

	ip = ip_hdr_get(pkt);
	return (ip->ver_ihl & 0x0F) * 4;
}

/**
@brief ip_tot_len_get 함수

주어진 패킷의 ip 패킷 전체 길이 반환

@param pkt pkt_t 구조체
@return ip 패킷의 전체 길이
*/
uint16_t ip_tot_len_get(pkt_t *pkt)
{
	ip_hdr_t *ip;

	ip = ip_hdr_get(pkt);
	return ntohs(ip->tot_len);
}

/**
@brief ip_checksum_cal 함수

ip checksum 값 계산 후 반환

@param ip_hdr 계산에 사용될 ip 헤더
@param hdr_len ip 헤더의 크기
@return 계산된 checksum 값
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

/**
@brief ip_log 함수

주어진 패킷의 ip 정보를 로그에 출력

@param pkt pkt_t 구조체
@return void
*/
void ip_log(pkt_t *pkt)
{
	ip_hdr_t *ip;
	char src_ip_str[INET_ADDRSTRLEN];
	char dst_ip_str[INET_ADDRSTRLEN];

	if (pkt->ip_offset == 0) {
		return;
	}
	ip = ip_hdr_get(pkt);
	if (!inet_ntop(AF_INET, &ip->src_ip, src_ip_str, INET_ADDRSTRLEN)) {
		LOG(ERR, "%s", strerror(errno));
		return;
	} else if (!inet_ntop(AF_INET, &ip->dst_ip, dst_ip_str, INET_ADDRSTRLEN)) {
		LOG(ERR, "%s", strerror(errno));
		return;
	}
	LOG(INFO, "[IP]");
	LOG(INFO, "src_ip = [%s], dst_ip = [%s], protocol = [%hu], ip_size = [%u]",
		src_ip_str, dst_ip_str, ip->protocol, ip_hdr_len_get(pkt));
}

