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
/* TLS 메시지 식별 값 */
#define TLS_CCS 0x14 /**< TLS ChangeCipherSpec 메시지 식별 값 */
#define TLS_ALERT 0x15 /**< TLS Alert 메시지 식별 값 */
#define TLS_HANDSHAKE 0x16 /**< TLS Handshake 메시지 식별 값 */
#define TLS_APPLICATION 0x17 /**< TLS Application 메시지 식별 값 */
#define TLS_HEARTBEAT 0x18 /**< TLS Heartbeat 메시지 식별 값 */

/* TLS Handshake 메시지 식별 값 */
#define TLS_HANDSHAKE_CH 1 /**< Client Hello 메시지 식별 값 */
#define TLS_HANDSHAKE_SH 2 /**< Server Hello 메시지 식별 값 */
#define TLS_HANDSHAKE_NST 4 /**< New Session Ticket 메시지 식별 값 */
#define TLS_HANDSHAKE_EE 8 /**< Encrypted Extensions 메시지 식별 값 */
#define TLS_HANDSHAKE_CERT 11 /**< Certificate 메시지 식별 값 */
#define TLS_HANDSHAKE_SKE 12 /**< Server Key Exchange  메시지 식별 값 */
#define TLS_HANDSHAKE_CR 13 /**< Certificate Request 메시지 식별 값 */
#define TLS_HANDSHAKE_SHD 14 /**< Server Hello Done 메시지 식별 값 */
#define TLS_HANDSHAKE_CV 15 /**< Certificate Verify 메시지 식별 값 */
#define TLS_HANDSHAKE_CKE 16 /**< Client Key Exchange 메시지 식별 값 */
#define TLS_HANDSHAKE_FIN 20 /**< Finished 메시지 식별 값 */

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
void tls_sni_get(pkt_t *pkt);

#endif

