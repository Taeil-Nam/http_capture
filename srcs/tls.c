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

/**
@brief tls_rec_get 함수

주어진 패킷에서 TLS record 헤더 반환

@param pkt pkt_t 구조체
@return tls_rec_t * tls record 헤더 반환
*/
tls_rec_t *tls_rec_get(pkt_t *pkt)
{
	return (tls_rec_t *)(pkt->pkt_data + pkt->tls_rec_offset);
}

/**
@brief tls_hand_get 함수

주어진 패킷에서 TLS handshake 헤더 반환

@param pkt pkt_t 구조체
@return tls_hand_t * tls handshake 헤더 반환
*/
tls_hand_t *tls_hand_get(pkt_t *pkt)
{
	return (tls_hand_t *)(pkt->pkt_data + pkt->tls_hand_offset);
}

/**
@brief tls_sni_get 함수

TLS Client Hello 메시지의 sni 값 추출
SNI가 있는 경우 pkt->tls_sni에 SNI 값 저장
SNI가 없는 경우 pkt->tls_sni에 NULL 저장

@param pkt 패킷 데이터
@return void
*/
void tls_sni_get(pkt_t *pkt)
{
	tls_rec_t *tls_rec;
	tls_hand_t *tls_hand;
	const uint8_t *cur_ch_offset;
	uint32_t ch_len;
	uint8_t sid_len;
	uint16_t cip_suite_len;
	uint8_t comp_len;
	uint16_t ext_len;
	tls_ext_t *cur_ext;
	tls_ext_sn_t *ext_sn;

	pkt->tls_sni = NULL;

	if (pkt->tls_rec_offset == 0) {
		return;
	}

	/* TLS Record 파싱 */
	tls_rec = tls_rec_get(pkt);
	pkt->tls_hand_offset = pkt->tls_rec_offset + sizeof(tls_rec_t);
	if (tls_rec->type != TLS_HANDSHAKE) {
		return;
	}

	/* TLS Handshake 파싱 */
	tls_hand = tls_hand_get(pkt);
	pkt->tls_ch_offset = pkt->tls_hand_offset + sizeof(tls_hand_t);
	ch_len = 0;
	ch_len = (tls_hand->len[0] << 16) |
			(tls_hand->len[1] << 8) |
			(tls_hand->len[2]);
	if (tls_hand->type != TLS_HANDSHAKE_CH) {
		return;
	}

	/* TLS Client Hello 파싱 */
	cur_ch_offset = pkt->pkt_data + pkt->tls_ch_offset;
	pkt->tls_ext_offset = pkt->tls_ch_offset;

	/* version */
	cur_ch_offset += CH_VERSION_FIELD;
	pkt->tls_ext_offset += CH_VERSION_FIELD;

	/* random */
	cur_ch_offset += CH_RANDOM_FIELD;
	pkt->tls_ext_offset += CH_RANDOM_FIELD;

	/* Session id */
	sid_len = *(uint8_t *)cur_ch_offset;
	cur_ch_offset += CH_SID_FIELD + sid_len;
	pkt->tls_ext_offset += CH_SID_FIELD + sid_len;

	/* Cypher Suite */
	cip_suite_len = ntohs(*(uint16_t *)cur_ch_offset);
	cur_ch_offset += CH_CIP_SUITE_FIELD + cip_suite_len;
	pkt->tls_ext_offset += CH_CIP_SUITE_FIELD + cip_suite_len;

	/* Compression Method */
	comp_len = *(uint8_t *)cur_ch_offset;
	cur_ch_offset += CH_COMP_FIELD + comp_len;
	pkt->tls_ext_offset += CH_COMP_FIELD + comp_len;

	/* Extension이 없는 경우 */
	if (ch_len == pkt->tls_ext_offset) {
		return;
	}

	/* Extension */
	ext_len = ntohs(*(uint16_t *)cur_ch_offset);
	cur_ch_offset += CH_EXTENSION_FIELD;

	/* Extension 목록 중 SNI 찾아서 반환 */
	while (ext_len > 0) {
		cur_ext = (tls_ext_t *)cur_ch_offset;

		/* server_name extension */
		if (ntohs(cur_ext->type) == TLS_EXT_SN) {
			cur_ch_offset += sizeof(tls_ext_t);
			ext_sn = (tls_ext_sn_t *)cur_ch_offset;
			cur_ch_offset += sizeof(tls_ext_sn_t);
			pkt->tls_sni =
				strndup((const char *)cur_ch_offset, ext_sn->sni_len);
			return;
		}
		cur_ch_offset += sizeof(tls_ext_t) + ntohs(cur_ext->len);
		ext_len -= sizeof(tls_ext_t) + ntohs(cur_ext->len);
	}

	return;
}

