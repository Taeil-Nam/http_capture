/**
@file cfg.h
@author 남태일(taeil.nam@monitorapp.com)
@date 2025-07-15
@brief conf 파일 관련 헤더파일
*/

#ifndef CFG_H
#define CFG_H

#include <stdbool.h>

/*
********************************************************************************
* CONSTANTS
********************************************************************************
*/
#define CFG_FILE_PATH "/tmp/http_capture/conf" /**< conf 파일 경로 */
#define CFG_LOG_FILE_PATH "/tmp/http_capture/log" /**< log 파일 경로 */
#define CFG_DUMP_FILE_PATH "/tmp/http_capture/dump" /**< dump 파일 경로 */
#define MAX_CFG_LINE 1024 /**< conf 파일의 최대 라인 수 */
#define MAX_CFG_LEN 1024 /**< conf 파일 각 라인의 최대 길이 */

/* 필수 설정 KEY 값 */
#define CFG_NET_IF_NAME "net_if_name"
#define CFG_PKT_CNTS "pkt_cnts"
#define CFG_TARGET_IP "target_ip"
#define CFG_TARGET_PORT "target_port"
#define CFG_LOG_FILE "log_file"
#define CFG_DUMP_FILE "dump_file"

/*
********************************************************************************
* PROTOTYPES
********************************************************************************
*/
void cfg_parse(void);
bool cfg_file_is_modified(void);
bool cfg_log_is_used(void);
bool cfg_dump_is_used(void);
const char *cfg_val_find(const char *key);
void cfg_print(void);
void cfg_free(void);

#endif
