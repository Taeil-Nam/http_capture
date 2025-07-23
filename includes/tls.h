/**
@file tls.h
@author 남태일(taeil.nam@monitorapp.com)
@date 2025-07-23
@brief TLS 로직 관련 헤더 파일
*/

#ifndef TLS_H
#define TLS_H

#include <stdint.h>
#include "pkt_capture.h"

/*
********************************************************************************
* CONSTANTS
********************************************************************************
*/
#define TLS_HANDSHAKE 0x16 /**< TLS 핸드셰이크 메시지 식별 값 */
#define TLS_HANDSHAKE_CH 0x01 /**< TLS Client Hello 메시지 식별 값 */
#define TLS_EXT_SN 0 /**< TLS Extension Server Name 식별 값 */

/* Client Hello 메시지의 각 필드 크기 */
#define CH_VERSION_FIELD 2
#define CH_RANDOM_FIELD 32
#define CH_SID_FIELD 1
#define CH_CIP_SUITE_FIELD 2
#define CH_COMP_FIELD 1
#define CH_EXTENSION_FIELD 2


/*
********************************************************************************
* DATA TYPES
********************************************************************************
*/
typedef struct __attribute__((packed)) tls_rec {
	uint8_t type;
	uint16_t ver;
	uint16_t len;
} tls_rec_t;

typedef struct  __attribute__((packed)) tls_hand {
	uint8_t type;
	uint8_t len[3];
} tls_hand_t;

typedef struct __attribute__((packed)) tls_ext {
	uint16_t type;
	uint16_t len;
} tls_ext_t;

typedef struct __attribute__((packed)) tls_ext_sn {
	uint16_t len;
	uint8_t type;
	uint16_t sni_len;
} tls_ext_sn_t; 

/*
********************************************************************************
* PROTOTYPES
********************************************************************************
*/
tls_rec_t *tls_rec_get(const uint8_t *pkt_data);
tls_hand_t *tls_hand_get(const uint8_t *pkt_data);
const char *tls_sni_get(pkt_t *pkt);

#endif

