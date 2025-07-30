/**
@file tls.h
@author 남태일(taeil.nam@monitorapp.com)
@date 2025-07-23
@brief tls 로직 관련 헤더 파일
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
#define TLS_CCS 0x14 /**< tls changecipherspec 메시지 식별 값 */
#define TLS_ALERT 0x15 /**< tls alert 메시지 식별 값 */
#define TLS_HANDSHAKE 0x16 /**< tls handshake 메시지 식별 값 */
#define TLS_APPLICATION 0x17 /**< tls application 메시지 식별 값 */
#define TLS_HEARTBEAT 0x18 /**< tls heartbeat 메시지 식별 값 */

#define TLS_HANDSHAKE_CH 1 /**< client hello 메시지 식별 값 */
#define TLS_HANDSHAKE_SH 2 /**< server hello 메시지 식별 값 */
#define TLS_HANDSHAKE_NST 4 /**< new session ticket 메시지 식별 값 */
#define TLS_HANDSHAKE_EE 8 /**< encrypted extensions 메시지 식별 값 */
#define TLS_HANDSHAKE_CERT 11 /**< certificate 메시지 식별 값 */
#define TLS_HANDSHAKE_SKE 12 /**< server key exchange  메시지 식별 값 */
#define TLS_HANDSHAKE_CR 13 /**< certificate request 메시지 식별 값 */
#define TLS_HANDSHAKE_SHD 14 /**< server hello done 메시지 식별 값 */
#define TLS_HANDSHAKE_CV 15 /**< certificate verify 메시지 식별 값 */
#define TLS_HANDSHAKE_CKE 16 /**< client key exchange 메시지 식별 값 */
#define TLS_HANDSHAKE_FIN 20 /**< finished 메시지 식별 값 */

#define TLS_EXT_SN 0 /**< tls extension server name 식별 값 */

#define CH_VERSION_FIELD 2 /**< client hello version 필드 크기(bytes) */
#define CH_RANDOM_FIELD 32 /**< client hello random 필드 크기(bytes) */
#define CH_SID_FIELD 1 /**< client hello sessionid 필드 크기(bytes) */
#define CH_CIP_SUITE_FIELD 2 /**< client hello cipher suite 필드 크기(bytes) */
#define CH_COMP_FIELD 1 /**< client hello compression 필드 크기(bytes) */
#define CH_EXTENSION_FIELD 2 /**< client hello extension 필드 크기(bytes) */

/*
********************************************************************************
* DATA TYPES
********************************************************************************
*/
/**
@brief tls record를 나타내는 구조체
*/
typedef struct __attribute__((packed)) tls_rec {
	uint8_t type; /**< type */
	uint16_t ver; /**< version */
	uint16_t len; /**< length */
} tls_rec_t;

/**
@brief tls handshake를 나타내는 구조체
*/
typedef struct  __attribute__((packed)) tls_hand {
	uint8_t type; /**< type */
	uint8_t len[3]; /**< length(3) */
} tls_hand_t;

/**
@brief tls extension을 나타내는 구조체
*/
typedef struct __attribute__((packed)) tls_ext {
	uint16_t type; /**< type */
	uint16_t len; /**< length */
} tls_ext_t;

/**
@brief tls server name extension을 나타내는 구조체
*/
typedef struct __attribute__((packed)) tls_ext_sn {
	uint16_t len; /**< length */
	uint8_t type; /**< type */
	uint16_t sni_len; /**< sni length */
} tls_ext_sn_t; 

/*
********************************************************************************
* PROTOTYPES
********************************************************************************
*/
tls_rec_t *tls_rec_get(pkt_t *pkt, uint16_t offset);
tls_hand_t *tls_hand_get(pkt_t *pkt, uint16_t offset);
void tls_sni_get(pkt_t *pkt);
void tls_log(pkt_t *pkt);

#endif

