/**
@file http.c
@author 남태일(taeil.nam@monitorapp.com)
@date 2025-07-30
@brief http 로직 관련 코드
*/

#include <stdlib.h>
#include <string.h>
#include "log.h"
#include "http.h"
#include "tcp.h"

/**
@brief http_log 함수

주어진 패킷의 http 정보를 log로 출력

@param pkt pkt_t 구조체
@return void
*/
void http_log(pkt_t *pkt)
{
	const uint8_t *http;
	const char *http_str;

	if (tcp_data_len_get(pkt) == 0) {
		return;
	}
	http = pkt->pkt_data + pkt->tcp_data_offset;
	http_str = strndup((const char *)http, tcp_data_len_get(pkt));
	LOG(INFO, "[HTTP]\n%s", http_str);
	free((void *)http_str);
}
