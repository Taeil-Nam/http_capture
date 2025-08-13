/**
@file tls.c
@author 남태일(taeil.nam@monitorapp.com).
@date 2025-07-22.
@brief tls 로직 관련 코드.
*/

#include <arpa/inet.h>
#include <string.h>
#include "tls.h"
#include "tcp.h"
#include "log.h"

/*
********************************************************************************
* PROTOTYPES
********************************************************************************
*/
static void tls_hand_log(uint8_t type);

/**
@brief tls_rec_get 함수.

주어진 패킷의 tls record 헤더 반환.

@param pkt pkt_t 구조체.
@param offset tls record offset.
@return tls record 헤더 반환.
*/
tls_rec_t *tls_rec_get(pkt_t *pkt, uint16_t offset)
{
	return (tls_rec_t *)(pkt->pkt_data + offset);
}

/**
@brief tls_hand_get 함수.

주어진 패킷에서 tls handshake 헤더 반환.

@param pkt pkt_t 구조체.
@param offset tls handshake offset.
@return tls handshake 헤더 반환.
*/
tls_hand_t *tls_hand_get(pkt_t *pkt, uint16_t offset)
{
	return (tls_hand_t *)(pkt->pkt_data + offset);
}

/**
@brief tls_sni_get 함수.

tls client hello 메시지의 sni 값 추출.
sni가 있는 경우 pkt->tls_sni에 sni 값 저장.
sni가 없는 경우 pkt->tls_sni에 null 저장.

@param pkt pkt_t 구조체.
@return void.
*/
void tls_sni_get(pkt_t *pkt)
{
	tls_rec_t *tls_rec;
	tls_hand_t *tls_hand;
	uint16_t tls_hand_offset;
	uint32_t ch_offset;
	uint32_t ext_offset;
	const uint8_t *cur_ch;
	uint32_t ch_len;
	uint8_t sid_len;
	uint16_t cip_suite_len;
	uint8_t comp_len;
	uint16_t ext_len;
	tls_ext_t *cur_ext;
	tls_ext_sn_t *ext_sn;

	pkt->tls_sni = NULL;

	/* tls 최소 크기보다 작은 경우 생략 */
	if (tcp_data_len_get(pkt) < 5) {
		return;
	}

	/* tls record 파싱 */
	tls_rec = tls_rec_get(pkt, pkt->tcp_data_offset);
	tls_hand_offset = pkt->tcp_data_offset + sizeof(tls_rec_t);
	if (tls_rec->type != TLS_HANDSHAKE) {
		return;
	}

	/* tls handshake 파싱 */
	tls_hand = tls_hand_get(pkt, tls_hand_offset);
	ch_offset = tls_hand_offset + sizeof(tls_hand_t);
	ch_len = 0;
	ch_len = (tls_hand->len[0] << 16) |
			(tls_hand->len[1] << 8) |
			(tls_hand->len[2]);
	if (tls_hand->type != TLS_HANDSHAKE_CH) {
		return;
	}

	/* tls client hello 파싱 */
	cur_ch = pkt->pkt_data + ch_offset;
	ext_offset = ch_offset;

	/* version */
	cur_ch += CH_VERSION_FIELD;
	ext_offset += CH_VERSION_FIELD;

	/* random */
	cur_ch += CH_RANDOM_FIELD;
	ext_offset += CH_RANDOM_FIELD;

	/* session id */
	sid_len = *(uint8_t *)cur_ch;
	cur_ch += CH_SID_FIELD + sid_len;
	ext_offset += CH_SID_FIELD + sid_len;

	/* cypher suite */
	cip_suite_len = ntohs(*(uint16_t *)cur_ch);
	cur_ch += CH_CIP_SUITE_FIELD + cip_suite_len;
	ext_offset += CH_CIP_SUITE_FIELD + cip_suite_len;

	/* compression method */
	comp_len = *(uint8_t *)cur_ch;
	cur_ch += CH_COMP_FIELD + comp_len;
	ext_offset += CH_COMP_FIELD + comp_len;

	/* extension이 없는 경우 생략 */
	if (ch_len == ext_offset - ch_offset) {
		return;
	}

	/* extension 파싱 */
	ext_len = ntohs(*(uint16_t *)cur_ch);
	cur_ch += CH_EXTENSION_FIELD;

	/* extension 목록 중 sni 찾아서 반환 */
	while (ext_len > 0) {
		cur_ext = (tls_ext_t *)cur_ch;

		/* server_name extension인 경우 sni 추출 */
		if (ntohs(cur_ext->type) == TLS_EXT_SN) {
			cur_ch += sizeof(tls_ext_t);
			ext_sn = (tls_ext_sn_t *)cur_ch;
			cur_ch += sizeof(tls_ext_sn_t);
			pkt->tls_sni =
				strndup((const char *)cur_ch, ntohs(ext_sn->sni_len));
			return;
		}
		cur_ch += sizeof(tls_ext_t) + ntohs(cur_ext->len);
		ext_len -= sizeof(tls_ext_t) + ntohs(cur_ext->len);
	}
}

/**
@brief tls_log 함수.

주어진 패킷에서 tls 정보 로깅.

@param pkt pkt_t 구조체.
@return void.
*/
void tls_log(pkt_t *pkt)
{
	tcp_hdr_t *tcp;
	uint16_t tcp_data_len;
	uint32_t tls_rec_offset;
	tls_rec_t *tls_rec;
	tls_hand_t *tls_hand;

	tcp = tcp_hdr_get(pkt);
	tcp_data_len = tcp_data_len_get(pkt);

	/* tls가 아니거나, tls 최소 크기보다 작으면 생략 */
	if ((ntohs(tcp->src_port) != 443 && ntohs(tcp->dst_port) != 443) ||
		tcp_data_len < 5) {
		return;
	}

	/* tls log 생성 */
	tls_rec_offset = pkt->tcp_data_offset;
	do {
		tls_rec = (tls_rec_t *)(pkt->pkt_data + tls_rec_offset);
		switch (tls_rec->type) {
		case TLS_CCS:
			LOG(INFO, "[TLS]");
			LOG(INFO, "ChangeCipherSpec Message");
			break;
		case TLS_ALERT:
			LOG(INFO, "[TLS]");
			LOG(INFO, "Alert Message");
			break;
		case TLS_HANDSHAKE:
			LOG(INFO, "[TLS]");
			LOG(INFO, "Handshake Message");
			tls_hand = (tls_hand_t *)(pkt->pkt_data +
				tls_rec_offset + sizeof(tls_rec_t));
			tls_hand_log(tls_hand->type);
			if (pkt->tls_sni) {
				LOG(INFO, "SNI = [%s]", pkt->tls_sni);
			}
			break;
		case TLS_APPLICATION:
			LOG(INFO, "[TLS]");
			LOG(INFO, "Application Message");
			break;
		case TLS_HEARTBEAT:
			LOG(INFO, "[TLS]");
			LOG(INFO, "Heartbeat Message");
			break;
		default:
			break;
		}
		tls_rec_offset += sizeof(tls_rec_t) + ntohs(tls_rec->len);

	} while (tls_rec_offset + sizeof(tls_rec_t) <
			pkt->tcp_data_offset + tcp_data_len);
}

/**
@brief tls_hand_log 정적 함수.

주어진 tls handskahe 타입에 맞는 log 출력.

@param type tls handshake 타입.
@return void.
*/
static void tls_hand_log(uint8_t type)
{
	switch (type) {
	case TLS_HANDSHAKE_CH:
		LOG(INFO, "Client Hello");
		break;
	case TLS_HANDSHAKE_SH:
		LOG(INFO, "Server Hello");
		break;
	case TLS_HANDSHAKE_NST:
		LOG(INFO, "New Session Ticket");
		break;
	case TLS_HANDSHAKE_EE:
		LOG(INFO, "Encrypted Extensions");
		break;
	case TLS_HANDSHAKE_CERT:
		LOG(INFO, "Certificate");
		break;
	case TLS_HANDSHAKE_SKE:
		LOG(INFO, "Server Key Exchange");
		break;
	case TLS_HANDSHAKE_CR:
		LOG(INFO, "Certificate Request");
		break;
	case TLS_HANDSHAKE_SHD:
		LOG(INFO, "Server Hello Done");
		break;
	case TLS_HANDSHAKE_CV:
		LOG(INFO, "Certificate Verify");
		break;
	case TLS_HANDSHAKE_CKE:
		LOG(INFO, "Client Key Exchange");
		break;
	case TLS_HANDSHAKE_FIN:
		LOG(INFO, "Finished");
		break;
	default:
		break;
    }
}

