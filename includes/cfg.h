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
#define CFG_FILE_PATH "/http_capture/conf" /**< conf 파일 경로 */
#define CFG_LOG_FILE_PATH "/http_capture/log" /**< log 파일 경로 */
#define CFG_DUMP_FILE_PATH "/http_capture/dump.pcap" /**< dump 파일 경로 */
#define MAX_CFG_CNTS 1024 /**< conf 파일의 최대 설정 개수 */
#define MAX_CFG_LEN 1024 /**< conf 파일 각 설정의 최대 길이 */
#define MAX_CFG_INTERVAL 3600 /**< conf 파일 확인 간격 최대값(초) */

#define CFG_NET_IF_NAME "net_if_name" /**< 네트워크 인터페이스 설정 key 값 */
#define CFG_PKT_CNTS "pkt_cnts" /**< 패킷 개수 설정 key 값 */
#define CFG_TARGET_IP "target_ip" /**< ip 필터링 설정 key 값 */
#define CFG_TARGET_PORT "target_port" /**< port number 필터링 설정 key 값 */
#define CFG_LOG_FILE "log_file" /**< log 파일 설정 key 값 */
#define CFG_DUMP_FILE "dump_file" /**< dump 파일 설정 key 값 */
#define CFG_SNI_RST "sni_rst" /**< sni로 rst 패킷 전송 설정 key 값 */
#define CFG_INTERVAL "cfg_interval" /**< conf 파일 확인 간격 key 값 */

/*
********************************************************************************
* PROTOTYPES
********************************************************************************
*/
void cfg_apply(void);
bool cfg_file_is_modified(void);
bool cfg_log_is_used(void);
bool cfg_dump_is_used(void);
bool cfg_sni_rst_is_used(void);
int cfg_interval_get(void);
const char *cfg_val_find(const char *key);
void cfg_print(void);
void cfg_free(void);

#endif

