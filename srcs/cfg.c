/**
@file cfg.c
@author 남태일(taeil.nam@monitorapp.com)
@date 2025-07-15
@brief conf 파일 관련 코드
*/

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "cfg.h"
#include "log.h"
#include "pkt_capture.h"

/*
********************************************************************************
* DATA TYPES
********************************************************************************
*/
/**
@brief conf 파일의 각 설정을 나타내는 구조체
*/
typedef struct cfg_entry {
	const char *key; /**< 설정의 key 값 */
	const char *value; /**< 설정의 value 값 */
} cfg_entry_t;

/*
********************************************************************************
* VARIABLES
********************************************************************************
*/
static FILE *cfg_file;
static cfg_entry_t cfg_entries[MAX_CFG_CNTS];
static int cfg_entry_cnts;
static time_t cfg_last_mtime;
static bool log_used;
static bool dump_used;
static bool sni_rst_used;

/*
********************************************************************************
* PROTOTYPES
********************************************************************************
*/
static int cfg_parse(void);
static int cfg_verify(void);
static int cfg_key_verify(void);
static int cfg_val_verify(void);
static void cfg_info_save(void);
static void cfg_last_mtime_update(void);
static void cfg_invalid_err(int);
static bool cfg_has_num(const char *str);

/**
@brief cfg_apply 함수

conf 파일 파싱, 검증 후 설정 적용 로직을 수행
설정 관련 오류 발생 시, CFG_INTERVAL 마다 conf 파일 재파싱 및 검증 수행
설정이 정상적으로 완료되면 종료
*/
void cfg_apply(void)
{
	struct timespec start_time, cur_time;
	int elapsed_time = 0;

	clock_gettime(CLOCK_MONOTONIC, &start_time);
	while (true) {
		cfg_free();
		if (cfg_parse() == 0 && cfg_verify() == 0) {
			break;
		}
		while (true) {
			clock_gettime(CLOCK_MONOTONIC, &cur_time);
			elapsed_time = cur_time.tv_sec - start_time.tv_sec;
			if (elapsed_time >= CFG_INTERVAL) {
				start_time = cur_time;
				break;
			}
			usleep(10000);
		}
	}
	cfg_last_mtime_update();
	cfg_info_save();
}

/**
@brief cfg_file_is_modified 함수

conf 파일의 수정 여부 반환

@param void
@return 수정된 경우 true, 최신 상태거나 오류 발생 시 false 반환
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
@return 사용 중인 경우 true, 아닌 경우 false 반환
*/
bool cfg_log_is_used(void)
{
	return log_used;
}

/**
@brief cfg_dump_is_used 함수

dump 파일 사용 유무 반환

@param void
@return 사용 중인 경우 true, 아닌 경우 false 반환
*/
bool cfg_dump_is_used(void)
{
	return dump_used;
}

/**
@brief cfg_sni_rst_is_used 함수

sni로 rst 패킷 전송 사용 유무 반환

@param void
@return 사용 중인 경우 true, 아닌 경우 false 반환
*/
bool cfg_sni_rst_is_used(void)
{
	return sni_rst_used;
}

/**
@brief cfg_val_find 함수

입력받은 key값의 value를 반환
시간 복잡도 = O(m * n)
m = conf 파일의 설정 개수
n = 입력된 key 문자열의 길이

@param key key 값
@return key가 존재하는 경우 value 반환, 존재하지 않는 경우 NULL 반환
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
	syslog(LOG_ERR, "There is no key(\"%s\") in configuration file.", key);
	return NULL;
}

/**
@brief cfg_print 함수

파싱된 conf 파일의 key, value 값들을 syslog에 출력

@param void
@return void
*/
void cfg_print(void)
{
	struct tm *t = localtime(&cfg_last_mtime);
	char time_buf[32];

	strftime(time_buf, sizeof(time_buf),"%Y-%m-%d %H:%M:%S", t);
	syslog(LOG_INFO, "Print configuration info...[START]");
	syslog(LOG_INFO, "cfg_last_mtime = %s", time_buf);
	for (int idx = 0; idx < cfg_entry_cnts; idx++) {
		syslog(LOG_INFO, "KEY = %s, VALUE = %s",
				cfg_entries[idx].key,
				cfg_entries[idx].value);
	}
	syslog(LOG_INFO, "Print configuration info...[DONE]");
}

/**
@brief cfg_free 함수

conf 파일에 관련된 모든 자원 반납

@param void
@return void
*/
void cfg_free(void)
{
	if (cfg_file) {
		fclose(cfg_file);
		cfg_file = NULL;
	}
	for (int idx = 0; idx < cfg_entry_cnts; idx++) {
		free((void *)cfg_entries[idx].key);
		free((void *)cfg_entries[idx].value);
		cfg_entries[idx].key = NULL;
		cfg_entries[idx].value = NULL;
	}
}

/**
@brief cfg_parse 정적 함수

conf 파일 파싱 후, 각 설정을 cfg_entries에 저장
각 설정의 key, value 값을 cfg_entries[idx]에 순서대로 저장
key, value는 동적 할당
시간복잡도 = O(m * n)
m = conf 파일의 설정 개수
n = 각 설정의 길이

@param void
@return 성공 시 0 반환, 실패 시 -1 반환
*/
static int cfg_parse(void)
{
	char line[MAX_CFG_LEN];
	int line_cnts = 0;

	syslog(LOG_INFO, "Parsing configuration file...[START]");
	cfg_file = fopen(CFG_FILE_PATH, "r");
	if (!cfg_file) {
		syslog(LOG_ERR, "Can't open configuration file(%s).", CFG_FILE_PATH);
		return -1;
	}
	while (fgets(line, sizeof(line), cfg_file)) {
		int start = 0;
		int end = 0;

		/* 주석이나 빈 줄 스킵 */
        if (line[0] == '#' || line[0] == '\n')
			continue;
		/* 설정에 '=' 미포함 시 종료 */
		if (!strchr(line, '=')) {
			cfg_invalid_err(line_cnts + 1);
			return -1;
		}
		/* key 값 파싱 */
		while (line[end] != '=') {
			/* key 값에 white space가 포함된 경우 종료 */
			if (isspace(line[end])) {
				cfg_invalid_err(line_cnts + 1);
				return -1;
			}
			end++;
		}
		/* key 값이 없는 경우 종료 */
		if (end - start == 0) {
			cfg_invalid_err(line_cnts + 1);
			return -1;
		}
		/* key 값 저장 */
		cfg_entries[line_cnts].key = strndup(&line[start], end - start);

		/* value 값 파싱 */
		end++;
		start = end;
		while (line[end] != '\n' && line[end] != '\0') {
			/* '=' 값이 중복된 경우 종료 */
			if (line[end] == '=') {
				cfg_invalid_err(line_cnts + 1);
				return -1;
			}
			/* value 값에 white space가 포함된 경우 종료 */
			if (isspace(line[end])) {
				cfg_invalid_err(line_cnts + 1);
				return -1;
			}
			end++;
		}
		/* value 값이 없는 경우 종료 */
		if (end - start == 0) {
			cfg_invalid_err(line_cnts + 1);
			return -1;
		}
		/* value 값 저장 */
		cfg_entries[line_cnts].value = strndup(&line[start], end - start);

		line_cnts++;
		if (line_cnts == MAX_CFG_CNTS) {
			break;
		}
	}
	cfg_entry_cnts = line_cnts;
	syslog(LOG_INFO, "Parsing configuration file...[DONE]");
	return 0;
}

/**
@brief cfg_verify 정적 함수

conf 파일로부터 파싱된 설정 검사

@param void
@return 검증 성공 시 0 반환, 검증 실패 시 -1 반환
*/
static int cfg_verify(void)
{
	syslog(LOG_INFO, "Verifying configuration file...[START]");
	if (cfg_key_verify() == -1 ||
		cfg_val_verify() == -1) {
		return -1;
	}
	syslog(LOG_INFO, "Verifying configuration file...[DONE]");
	return 0;
}

/**
@brief cfg_key_verify 정적 함수

필수 key 값들이 존재하는지 검사

@param void
@return 검증 성공 시 0 반환, 검증 실패 시 -1 반환
*/
static int cfg_key_verify(void)
{
	if (!cfg_val_find(CFG_NET_IF_NAME)) {
		syslog(LOG_ERR, "Configuration \"%s\" is required.", CFG_NET_IF_NAME);
		return -1;
	} else if (!cfg_val_find(CFG_PKT_CNTS)) {
		syslog(LOG_ERR, "Configuration \"%s\" is required.", CFG_PKT_CNTS);
		return -1;
	} else if (!cfg_val_find(CFG_TARGET_IP)) {
		syslog(LOG_ERR, "Configuration \"%s\" is required.", CFG_TARGET_IP);
		return -1;
	} else if (!cfg_val_find(CFG_TARGET_PORT)) {
		syslog(LOG_ERR, "Configuration \"%s\" is required.", CFG_TARGET_PORT);
		return -1;
	} else if (!cfg_val_find(CFG_LOG_FILE)) {
		syslog(LOG_ERR, "Configuration \"%s\" is required.", CFG_LOG_FILE);
		return -1;
	} else if (!cfg_val_find(CFG_DUMP_FILE)) {
		syslog(LOG_ERR, "Configuration \"%s\" is required.", CFG_DUMP_FILE);
		return -1;
	} else if (!cfg_val_find(CFG_SNI_RST)) {
		syslog(LOG_ERR, "Configuration \"%s\" is required.", CFG_SNI_RST);
		return -1;
	}
	return 0;
}

/**
@brief cfg_val_verify 정적 함수

conf 파일로부터 파싱된 value 값 검사

@param void
@return 검증 성공 시 0 반환, 검증 실패 시 -1 반환
*/
static int cfg_val_verify(void)
{
	const char *net_if_name;
	const char *pkt_cnts_str;
	int pkt_cnts;
	const char *target_ip;
	const char *target_port_str;
	int target_port;
	bool is_exist = false;
	struct ifaddrs *ifaddr, *ifa;
	struct in_addr ip_addr;


	/* 시스템의 네트워크 인터페이스 목록 불러오기 */
	if (getifaddrs(&ifaddr) == -1) {
	    syslog(LOG_ERR, "%s", strerror(errno));
		return -1;
	}
	/* net_if_name과 동일한 이름의 네트워크 인터페이스가 있는지 확인 */
	net_if_name = cfg_val_find(CFG_NET_IF_NAME);
	ifa = ifaddr;
	while (ifa) {
		if (strcmp(ifa->ifa_name, net_if_name) == 0) {
			is_exist = true;
			freeifaddrs(ifaddr);
			break;
		}
		ifa = ifa->ifa_next;
	}
	if (is_exist == false) {
		syslog(LOG_ERR, "There is no network interface(%s).", net_if_name);
		freeifaddrs(ifaddr);
		return -1;
	}
	/* pkt_cnts 값 검사 */
	pkt_cnts_str = cfg_val_find(CFG_PKT_CNTS);
	if (!cfg_has_num(pkt_cnts_str)) {
		syslog(LOG_ERR, "Invalid pkt_cnts(%s).", pkt_cnts_str);
		return -1;
	}
	pkt_cnts = atoi(cfg_val_find(CFG_PKT_CNTS));
	if (pkt_cnts < 0 || pkt_cnts > MAX_PKT_CNTS) {
		syslog(LOG_ERR, "Invalid pkt_cnts(%d).", pkt_cnts);
		return -1;
	}
	/* target_ip 값 검사 */
	target_ip = cfg_val_find(CFG_TARGET_IP);
	if ((inet_pton(AF_INET, target_ip, &ip_addr) != 1) &&
		(inet_pton(AF_INET6, target_ip, &ip_addr) != 1)) {
		syslog(LOG_ERR, "Invalid target_ip(%s).", target_ip);
		return -1;
	}
	/* target_port 값 검사 */
	target_port_str = cfg_val_find(CFG_TARGET_PORT);
	if (!cfg_has_num(target_port_str)) {
	    syslog(LOG_ERR, "Invalid target_port(%s).", target_port_str);
		return -1;
	}
	target_port = atoi(cfg_val_find(CFG_TARGET_PORT));
	if (target_port < 0 || target_port > 65535) {
	    syslog(LOG_ERR, "Invalid target_port(%d).", target_port);
		return -1;
	}
	return 0;
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
		dump_used = false;
	}
	/* SNI로 RESET 패킷 전송 사용 유무 저장 */
	if (strcmp(cfg_val_find(CFG_SNI_RST), "1") == 0) {
		sni_rst_used = true;
	} else {
		sni_rst_used = false;
	}
	syslog(LOG_INFO, "Saving configuration info...[DONE]");
}
/**
@brief cfg_last_mtime_update 정적 함수

conf 파일의 마지막 수정 시간 갱신
conf 파일 상태 읽기 오류 발생 시 0으로 갱신

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

conf 파일 파싱 중, 유효하지 않은 형식으로 설정되어 있는 경우 syslog 생성

@param line_num 오류에 해당하는 줄 번호
@return void
*/
static void cfg_invalid_err(int line_num)
{
	syslog(LOG_ERR, "invalid configuration file format at line %d.", line_num);
}

/**
@brief cfg_has_num 정적 함수

설정에 숫자가 포함되어 있는지 확인

@param str 확인할 설정 문자열
@return 숫자가 포함되어 있으면 true, 미포함 시 false 반환
*/
static bool cfg_has_num(const char *str)
{
	int idx = 0;

	while (str[idx]) {
		if (str[idx] >= '0' && str[idx] <= '9') {
			return true;
		}
		idx++;
	}
	return false;
}

