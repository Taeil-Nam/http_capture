/**
@file cfg.c
@author 남태일(taeil.nam@monitorapp.com)
@date 2025-07-15
@brief conf 파일 관련 코드 
*/

#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include "cfg.h"
#include "log.h"

/*
********************************************************************************
* DATA TYPES
********************************************************************************
*/

/* conf 파일의 각 라인 */
typedef struct cfg_entry {
	const char *key; /**< 라인의 key 값 */
	const char *value; /**< 라인의 value 값 */
} cfg_entry_t;

/*
********************************************************************************
* VARIABLES
********************************************************************************
*/
static cfg_entry_t cfg_entries[MAX_CFG_LINE]; /**< conf 파일 라인의 배열 */
static int cfg_entry_cnts; /**< 파싱된 라인 개수 */
static time_t cfg_last_mtime; /**< conf 파일 마지막 수정 시간 */
static bool log_used; /**< log 파일 사용 유무 */
static bool dump_used; /**< dump 파일 사용 유무 */

/*
********************************************************************************
* PROTOTYPES
********************************************************************************
*/
static void cfg_required_verify(void);
static void cfg_info_save(void);
static void cfg_last_mtime_update(void);
static void cfg_invalid_err(int);

/**
@brief cfg_parse 함수

conf 파일 파싱 후, cfg_entries에 저장
라인의 key, value 값을 cfg_entries[idx]에 순서대로 저장
conf 내용 형식이 잘못된 경우, 프로그램 종료
시간복잡도 = O(m * n)
m = conf 파일의 라인 수
n = 각 라인의 길이 


@param void
@return void
*/
void cfg_parse(void)
{
	FILE *cfg_file = NULL;
	char line[MAX_CFG_LEN];
	int line_cnts = 0;

	/* conf 파일 열기 */
	syslog(LOG_INFO, "Parsing configuration file...[START]");
	cfg_file = fopen(CFG_FILE_PATH, "r");
	if (!cfg_file) {
		syslog(LOG_ERR, "Can't open configuration file %s.", CFG_FILE_PATH);
		exit(EXIT_FAILURE);
	}

	/* conf 파일의 마지막 수정 시간 갱신 */
	cfg_last_mtime_update();

	/* conf 파일의 각 라인 파싱 */ 
	while (fgets(line, sizeof(line), cfg_file)) {
		int start = 0;
		int end = 0;

		/* 주석이나 빈 줄 스킵 */
        if (line[0] == '#' || line[0] == '\n')
			continue;

		/* line에 '='이 없는 경우 종료 */
		if (!strchr(line, '=')) {
			cfg_invalid_err(line_cnts + 1);
		}

		/* KEY 값 파싱 */
		while (line[end] != '=') {
			end++;
		}

		/* KEY 값이 없는 경우 종료 */
		if (end - start == 0) {
			cfg_invalid_err(line_cnts + 1);
		}

		/* KEY 값 저장 */
		cfg_entries[line_cnts].key = strndup(&line[start], end - start);

		/* VALUE 값 파싱 */
		end++;
		start = end;
		
		while (line[end] != '\n' && line[end] != '\0') {

			/* '=' 값이 중복된 경우 종료 */
			if (line[end] == '=') {
				cfg_invalid_err(line_cnts + 1);
			}
			end++;
		}

		/* VALUE 값이 없는 경우 종료 */
		if (end - start == 0) {
			cfg_invalid_err(line_cnts + 1);
		}

		/* VALUE 값 저장 */
		cfg_entries[line_cnts].value = strndup(&line[start], end - start);

		line_cnts++;

		/* 최대 라인 수 만큼 파싱 했으면 break */
		if (line_cnts == MAX_CFG_LINE) {
			break;
		}
	}

	/* 파싱된 라인 개수 저장 */
	cfg_entry_cnts = line_cnts;

	/* conf 파일 close */
	fclose(cfg_file);

	syslog(LOG_INFO, "Parsing configuration file...[DONE]");

	/* 필수 설정 검사 */
	cfg_required_verify();

	/* 설정 관련 정보 저장 */
	cfg_info_save();
}

/**
@brief cfg_file_is_modified 함수

conf 파일의 수정 여부 반환

@param void
@return bool 수정된 경우 true 반환, 최신 상태거나 오류 발생시 false 반환
*/
bool cfg_file_is_modified(void)
{
	struct stat file_stat;

	if (stat(CFG_FILE_PATH, &file_stat) == -1) {
		return false;
	}
	if (file_stat.st_mtim.tv_sec == cfg_last_mtime) {
		return false;
	}
	return true;
}

/**
@brief cfg_log_is_used 함수

log 파일 사용 유무 반환

@param void
@return bool log 파일 사용 중인 경우 true, 아닌 경우 false 반환 
*/
bool cfg_log_is_used(void)
{
	return log_used;
}

/**
@brief cfg_dump_is_used 함수

dump 파일 사용 유무 반환

@param void
@return bool dump 파일 사용 중인 경우 true, 아닌 경우 false 반환 
*/
bool cfg_dump_is_used(void)
{
	return dump_used;
}

/**
@brief cfg_val_find 함수

입력받은 key값의 value를 찾아 반환
시간 복잡도 = O(m * n)
m = conf 파일의 라인 수
n = 입력된 key 문자열의 길이

@param key 찾고 싶은 value의 key 값 
@return const char * 찾으면 value 반환, 못 찾으면 NULL 반환
*/
const char *cfg_val_find(const char *key)
{
	if (!key) {
		return NULL;
	}
	for (int idx = 0; idx < cfg_entry_cnts; idx++) {
		if (strcmp(cfg_entries[idx].key, key) == 0) {
			return cfg_entries[idx].value;
		}
	}
	LOG(WARN, "There is no \"%s\" in configuration file.", key);
	return NULL;
}

/**
@brief cfg_print 함수

파싱된 conf 파일의 key, value 값들을 log 파일에 출력

@param void
@return void
*/
void cfg_print(void)
{
	LOG(INFO, "=== STARTED PRINT CONF FILE ===");

	for (int idx = 0; idx < cfg_entry_cnts; idx++) {
		LOG(INFO, "KEY = %s, VALUE = %s",
				cfg_entries[idx].key,
				cfg_entries[idx].value);
	}
	LOG(INFO, "cfg_last_mtime = %ld", cfg_last_mtime);

	LOG(INFO, "=== FINISED PRINT CONF FILE ===");
}

/**
@brief cfg_free 함수

모든 cfg_entry_t 구조체의 key, value 값 메모리 반납

@param void
@return void
*/
void cfg_free(void)
{
	for (int idx = 0; idx < cfg_entry_cnts; idx++) {
		free((void *)cfg_entries[idx].key);
		free((void *)cfg_entries[idx].value);
		cfg_entries[idx].key = NULL;
		cfg_entries[idx].value = NULL;
	}
}

/**
@brief cfg_required_verify 정적 함수

conf 파일의 필수 설정 포함 여부 검사
필수 설정 없는 경우 프로그램 종료

@param void
@return void
*/
static void cfg_required_verify(void)
{
	syslog(LOG_INFO, "Verifying configuration file...[START]");

	if (!cfg_val_find(CFG_NET_IF_NAME)) {
		syslog(LOG_ERR, "Configuration \"%s\" is required.", CFG_NET_IF_NAME);
		exit(EXIT_FAILURE);
	} else if (!cfg_val_find(CFG_PKT_CNTS)) {
		syslog(LOG_ERR, "Configuration \"%s\" is required.", CFG_PKT_CNTS);
		exit(EXIT_FAILURE);
	} else if (!cfg_val_find(CFG_TARGET_IP)) {
		syslog(LOG_ERR, "Configuration \"%s\" is required.", CFG_TARGET_IP);
		exit(EXIT_FAILURE);
	} else if (!cfg_val_find(CFG_TARGET_PORT)) {
		syslog(LOG_ERR, "Configuration \"%s\" is required.", CFG_TARGET_PORT);
		exit(EXIT_FAILURE);
	} else if (!cfg_val_find(CFG_LOG_FILE)) {
		syslog(LOG_ERR, "Configuration \"%s\" is required.", CFG_LOG_FILE);
		exit(EXIT_FAILURE);
	} else if (!cfg_val_find(CFG_DUMP_FILE)) {
		syslog(LOG_ERR, "Configuration \"%s\" is required.", CFG_DUMP_FILE);
		exit(EXIT_FAILURE);
	} 

	syslog(LOG_INFO, "Verifying configuration file...[DONE]");
}

/**
@brief cfg_info_save 정적 함수

설정 관련 정보 저장

@param void
@return void
*/
static void cfg_info_save(void)
{
	syslog(LOG_INFO, "Saving configuration info...[START]");

	/* log 파일 사용 유무 저장 */
	if (strcmp(cfg_val_find(CFG_LOG_FILE), "1") == 0) {
		log_used = true;
	} else {
		log_used = false;
	}

	/* dump 파일 사용 유무 저장 */
	if (strcmp(cfg_val_find(CFG_DUMP_FILE), "1") == 0) {
		dump_used = true;
	} else {
		log_used = false;
	}

	syslog(LOG_INFO, "Saving configuration info...[DONE]");
}
/**
@brief cfg_last_mtime_update 정적 함수

conf 파일의 마지막 수정 시간 갱신
conf 파일 상태 읽기 오류시 0으로 갱신

@param void
@return void
*/
static void cfg_last_mtime_update(void)
{
	struct stat file_stat;

	if (stat(CFG_FILE_PATH, &file_stat) == -1) {
		cfg_last_mtime = 0;
	}
	else {
		cfg_last_mtime = file_stat.st_mtime;
	}
}

/**
@brief cfg_invalid_err 정적 함수

conf 파일 파싱 중, 유효하지 않은 형식으로 설정되어 있는 경우 호출

@param line_num 오류에 해당하는 줄 번호
@return void
*/
static void cfg_invalid_err(int line_num)
{
	syslog(LOG_ERR,
		"invalid configuration file format at line %d.",
		line_num);
	exit(EXIT_FAILURE);
}

