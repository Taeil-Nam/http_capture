/**
@file tls.c
@author 남태일(taeil.nam@monitorapp.com)
@date 2025-07-22
@brief TLS 로직 관련 코드 
*/

#include <arpa/inet.h>
#include <string.h>
#include "log.h"
#include "tls.h"

/*
********************************************************************************
* DATA TYPES
********************************************************************************
*/

/*
********************************************************************************
* VARIABLES
********************************************************************************
*/

/*
********************************************************************************
* PROTOTYPES
********************************************************************************
*/

/**
@brief tls_sni_get 함수

TLS Client Hello 메시지의 sni 값 추출

@param ch Client Hello 메시지 데이터
@param ch_len Client Hello 메시지의 길이
@return const char * sni 문자열 포인터 반환, 실패시 NULL 반환
*/
const char *tls_sni_get(const uint8_t *ch, uint32_t ch_len)
{
	const uint8_t *offset = ch;
	uint8_t sid_len;
	uint16_t cip_suite_len;
	uint8_t comp_len;
	uint16_t extension_len;
	struct tls_extension *cur_ext;
	struct ext_server_name *ext_server_name;

	/* version */
	offset += CH_VERSION_FIELD;
	ch_len -= CH_VERSION_FIELD;

	/* random */
	offset += CH_RAMDOM_FIELD;
	ch_len -= CH_RAMDOM_FIELD;

	/* Session id */
	sid_len = *(uint8_t *)offset;
	offset += CH_SID_FIELD + sid_len;
	ch_len -= CH_SID_FIELD + sid_len;

	/* Cypher Suite */
	cip_suite_len = ntohs(*(uint16_t *)offset);
	offset += CH_CIP_SUITE_FIELD + cip_suite_len;
	ch_len -= CH_CIP_SUITE_FIELD + cip_suite_len;


	/* Compression Method */
	comp_len = *(uint8_t *)offset;
	offset += CH_COMP_FIELD + comp_len;
	ch_len -= CH_COMP_FIELD + comp_len;

	/* Extension */
	extension_len = ntohs(*(uint16_t *)offset);
	offset += CH_EXTENSION_FIELD;
	ch_len -= CH_EXTENSION_FIELD;

	/* SNI 찾아서 추출하기 */
	while (extension_len > 0) {
		cur_ext = (struct tls_extension *)offset;

		/* server_name extension */
		if (cur_ext->type == 0) {
			offset += sizeof(struct tls_extension);
			ext_server_name = (struct ext_server_name *)offset;
			offset += sizeof(struct ext_server_name);
			return strndup((const char *)offset, ext_server_name->sni_len);
		}
		offset += cur_ext->len;
		extension_len -= cur_ext->len;
	}

	return NULL;
}

