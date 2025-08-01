/**
@file tcp.c
@author 남태일(taeil.nam@monitorapp.com)
@date 2025-07-23
@brief tcp 로직 관련 코드
*/

#include <arpa/inet.h>
#include "tcp.h"
#include "ip.h"
#include "log.h"

/*
********************************************************************************
DATA TYPES
********************************************************************************
*/
/**
@brief pseudo header를 나타내는 구조체
*/
typedef struct pseudo_hdr {
	uint32_t src_ip; /**< source ip */
	uint32_t dst_ip; /**< destination ip */
	uint8_t rsv; /**< reserve */
	uint8_t protocol; /**< protocol */
	uint16_t tcp_len; /**< tcp length */
} pseudo_hdr_t;

/**
@brief tcp_hdr_get 함수

주어진 패킷의 tcp 헤더 반환

@param pkt pkt_t 구조체
@return tcp_hdr_t 구조체 포인터 반환
*/
tcp_hdr_t *tcp_hdr_get(pkt_t *pkt)
{
	return (tcp_hdr_t *)(pkt->pkt_data + pkt->tcp_offset);
}

/**
@brief tcp_hdr_len_get 함수

주어진 패킷의 tcp 헤더 길이 반환

@param pkt pkt_t 구조체
@return tcp 헤더 길이
*/
uint8_t tcp_hdr_len_get(pkt_t *pkt)
{
	tcp_hdr_t * tcp;

	tcp = tcp_hdr_get(pkt);
	return (tcp->off_rsv >> 4) * 4;
}

/**
@brief tcp_data_len_get 함수

주어진 패킷의 tcp data 길이 반환

@param pkt pkt_t 구조체
@return tcp data 길이
*/
uint16_t tcp_data_len_get(pkt_t *pkt)
{
	return ip_tot_len_get(pkt) - ip_hdr_len_get(pkt) - tcp_hdr_len_get(pkt);
}

/**
@brief tcp_checksum_cal 함수

tcp checksum 값 계산 후 반환

@param ip_hdr 계산에 사용될 ip 헤더
@param tcp 계산에 사용될 tcp 세그먼트
@param tcp_len tcp 세그먼트의 길이
@return 계산된 tcp checksum 값
*/
uint16_t tcp_checksum_cal(uint8_t *ip_hdr, uint8_t *tcp, int tcp_len)
{
	pseudo_hdr_t pseudo_hdr;
	int pseudo_hdr_len = PSEUDO_HDR_LEN;
	uint16_t *data;
	uint32_t checksum = 0;

	pseudo_hdr.src_ip = ((ip_hdr_t *)ip_hdr)->src_ip;
	pseudo_hdr.dst_ip = ((ip_hdr_t *)ip_hdr)->dst_ip;
	pseudo_hdr.rsv = 0;
	pseudo_hdr.protocol = ((ip_hdr_t *)ip_hdr)->protocol;
	pseudo_hdr.tcp_len = htons(tcp_len);
	/* pseudo header checksum 계산 */
	data = (uint16_t *)(&pseudo_hdr);
	while (pseudo_hdr_len > 0) {
		checksum += ntohs(*data);
		data++;
		pseudo_hdr_len -= 2;
	}
	/* tcp 세그먼트 checksum 계산 */
	data = (uint16_t *)tcp;
	while (tcp_len > 1) {
		checksum += ntohs(*data);
		data++;
		tcp_len -= 2;
	}
	if (tcp_len == 1) {
		checksum += *((uint8_t *)data);
	}
	checksum = (checksum >> 16) + (checksum & 0xFFFF);
	checksum += (checksum >> 16);
	return htons((uint16_t)(~checksum));
}

/**
@brief tcp_log 함수

주어진 패킷의 tcp 정보를 log로 출력

@param pkt pkt_t 구조체
@return void
*/
void tcp_log(pkt_t *pkt)
{
	tcp_hdr_t *tcp;
	const char *flag_list = "CEUAPRSF";
	char flags[9];
	int flag_offset = 0x80;

	if (pkt->tcp_offset == 0) {
		return;
	}
	tcp = tcp_hdr_get(pkt);
	LOG(INFO, "[TCP]");
	LOG(INFO, "src_port = [%hu], dst_port = [%hu], tcp_size = [%hu]",
		ntohs(tcp->src_port), ntohs(tcp->dst_port), tcp_hdr_len_get(pkt));
	LOG(INFO, "seq_num = [%u], ack_num = [%u], data_len = [%u], window = [%hu]",
		ntohl(tcp->seq_num), ntohl(tcp->ack_num),
		tcp_data_len_get(pkt), ntohs(tcp->window));
	/* TCP flag 정보 출력 */
	for (int idx = 0; idx < 8; idx++) {
        if (tcp->flags & flag_offset) {
            flags[idx] = flag_list[idx];
        } else {
            flags[idx] = '.';
        }
        flag_offset = flag_offset >> 1;
    }
    flags[8] = '\0';
    LOG(INFO, "flags = [%s]", flags);
}

