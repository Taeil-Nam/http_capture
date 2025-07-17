/**
@file log.c
@author 남태일(taeil.nam@monitorapp.com)
@date 2025-07-17
@brief log 관련 코드 
*/

#include <stdarg.h>
#include <stdlib.h>
#include <syslog.h>
#include <time.h>
#include "log.h"

/*
********************************************************************************
* DATA TYPES
********************************************************************************
*/
FILE *g_log_file = NULL;

/**
@brief log_file_open 함수

conf 파일에서 log 파일 경로를 찾고, 해당 경로에 log 파일을 생성
log 파일은 append 모드, 즉시 출력 모드로 생성
log 파일 관련 설정이 없거나, log 파일 생성 실패시 프로그램 종료

@param void
@return void 
*/
void log_file_open(void)
{
	const char *log_file_path = NULL;

	/* conf 파일에서 log 파일 경로 찾기 */
	log_file_path = cfg_val_find(CFG_LOG_FILE_PATH);
	if (!log_file_path) {
		syslog(LOG_ERR, "Count't find \"%s\" in configuration file.",
				CFG_LOG_FILE_PATH);
		exit(EXIT_FAILURE);
	}
	
	/* log 파일 생성 */
	g_log_file = fopen(log_file_path, "a");
	if (!g_log_file) {
		syslog(LOG_ERR, "Failed to create log file(%s).", log_file_path);
		exit(EXIT_FAILURE);
	}

	/* 버퍼링 사용 없이 즉시 출력 */
	setvbuf(g_log_file, NULL, _IONBF, 0);

	/* log 파일 생성 알림 */
	LOG(INFO, "\n\n===NEW LOGGING STARTED===");
}

/**
@brief log_write 함수

log 파일에 로그를 출력
입력된 level과 문자열 포맷에 맞게 log를 출력
날짜, level, 함수명, 문자열 순서로 log를 출력
자동으로 줄바꿈 지원

@param level log 레벨
@param func log를 출력한 함수
@param fmt log 문자열 형식
@param ... log 문자열 형식에 포함된 가변 인자
@return void 
*/
void log_write(const char *level, const char *func, const char *fmt, ...)
{
	time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char time_buf[32];
    va_list args;

    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", t);

    fprintf(g_log_file, "[%s][%s][%s] ", time_buf, level, func);
    va_start(args, fmt);
    vfprintf(g_log_file, fmt, args);
    va_end(args);
	fprintf(g_log_file, "\n");
}

/**
@brief log_file_close 함수

log 파일 close

@param void
@return void 
*/
void log_file_close(void)
{
	fclose(g_log_file);
}

