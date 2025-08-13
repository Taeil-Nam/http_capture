/**
@file http.c
@author 남태일(taeil.nam@monitorapp.com).
@date 2025-07-30.
@brief http 로직 관련 코드.
*/

#include <stdlib.h>
#include <string.h>
#include "log.h"
#include "http.h"
#include "tcp.h"

/**
@brief http_log 함수.

주어진 패킷의 http 정보를 log로 출력.

@param pkt pkt_t 구조체.
@return void.
*/
void http_log(pkt_t *pkt)
{
	tcp_hdr_t *tcp;
	const uint8_t *http;
	const char *http_str;

	/* http 패킷이 아니거나 http 데이터가 없는 경우 */
	tcp = tcp_hdr_get(pkt);
	if ((ntohs(tcp->src_port) != 80 && ntohs(tcp->dst_port) != 80) ||
		tcp_data_len_get(pkt) == 0) {
		return;
	}

	/* http log 생성 */
	http = pkt->pkt_data + pkt->tcp_data_offset;
	http_str = strndup((const char *)http, tcp_data_len_get(pkt));
	LOG(INFO, "[HTTP]\n%s", http_str);
	free((void *)http_str);
}

