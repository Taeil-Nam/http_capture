/**
@file cfg_parse.h
@author 남태일(taeil.nam@monitorapp.com)
@date 2025-07-15
@brief conf 파일 파싱을 위한 헤더파일
*/

#ifndef CFG_PARSE_H
#define CFG_PARSE_H

/*
********************************************************************************
* CONSTANTS
********************************************************************************
*/

#define CFG_FILE_PATH "/tmp/conf/conf" /**< conf 파일 경로 */
#define CFG_PARSE_TEST_PATH "/tmp/conf/test" // test code (삭제 필요)
#define MAX_PARSE_LINE 1024 /**< 파싱 가능한 conf 파일의 최대 라인 수 */

/*
********************************************************************************
* DATA TYPES
********************************************************************************
*/
/**
@brief cfg_entry 구조체 
conf 파일 각 라인의 key, value 값을 저장하는 구조체
*/
typedef struct cfg_entry {
	const char *key; /**< line의 key 값 */
	const char *value; /**< line의 value 값 */
} cfg_entry_t;


/*
********************************************************************************
* EXTERNALS 
********************************************************************************
*/
extern int g_cfg_entry_cnts; /**< 파싱 완료된 conf 파일의 entry 개수 */

/*
********************************************************************************
* PROTOTYPES
********************************************************************************
*/
void cfg_parse(cfg_entry_t *cfg_entries);

#endif
