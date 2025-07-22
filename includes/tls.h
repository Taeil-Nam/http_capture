/**
@file tls.h
@author 남태일(taeil.nam@monitorapp.com)
@date 2025-07-22
@brief TLS 로직 관련 헤더 파일
*/

#ifndef TLS_H
#define TLS_H

#include <stdint.h>

/*
********************************************************************************
* CONSTANTS
********************************************************************************
*/
#define CH_VERSION_FIELD 2
#define CH_RAMDOM_FIELD 32
#define CH_SID_FIELD 1
#define CH_CIP_SUITE_FIELD 2
#define CH_COMP_FIELD 1
#define CH_EXTENSION_FIELD 2

/*
********************************************************************************
* DATA TYPES
********************************************************************************
*/
struct tls_rec {
	unsigned char type;
	unsigned short ver;
	unsigned short len;
} __attribute__((packed));

struct tls_hand {
	unsigned char type;
	unsigned char len[3];
} __attribute__((packed));

struct tls_extension {
	unsigned short type;
	unsigned short len;
} __attribute__((packed));

struct ext_server_name {
	unsigned short len;
	unsigned char type;
	unsigned short sni_len;
} __attribute__((packed));

/*
********************************************************************************
* PROTOTYPES
********************************************************************************
*/
const char *tls_sni_get(const uint8_t *ch, const uint32_t len);

#endif

