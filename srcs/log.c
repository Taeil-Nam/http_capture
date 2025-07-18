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
static FILE *log_file = NULL;

/**
@brief log_file_open 함수

conf 파일에 log 파일 사용이 명시되어있을 경우(1) log 파일 생성
log 파일을 append 모드, 즉시 출력 모드로 생성
log 파일 생성 실패시 프로그램 종료

@param void
@return void 
*/
void log_file_open(void)
{
	/* log 파일 미사용시 생략 */
	if (!cfg_log_is_used()) {
		return;
	}

	/* log 파일 생성 */
	log_file = fopen(CFG_LOG_FILE_PATH, "a");

	/* log 파일 생성 실패시 프로그램 종료 */
	if (!log_file) {
		syslog(LOG_ERR, "Failed to create log file(%s).", CFG_LOG_FILE_PATH);
		exit(EXIT_FAILURE);
	}

	/* 버퍼링 사용 없이 즉시 출력 */
	setvbuf(log_file, NULL, _IONBF, 0);

	/* log 파일 생성 알림 */
	syslog(LOG_INFO, "===LOG FILE CREATED===");
	fputs("\n\n===NEW LOGGING STARTED===\n", log_file);
}

/**
@brief log_wr 함수

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
void log_wr(const char *level, const char *file,
		int line, const char *fmt, ...)
{
	time_t now = time(NULL);
	struct tm *t = localtime(&now);
	char time_buf[32];
	va_list args;

	/* log 파일 미사용시 생략 */
	if (!cfg_log_is_used()) {
		return;
	}

	/* 시간을 주어진 문자열 형식으로 변환 */
	strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", t);
	
	/* log 출력 */
	fprintf(log_file, "[%s][%s] [%s:%d] ",
			time_buf, level, file, line);
	va_start(args, fmt);
	vfprintf(log_file, fmt, args);
	va_end(args);
	fprintf(log_file, "\n");
}

/**
@brief log_file_close 함수

log 파일 close

@param void
@return void 
*/
void log_file_close(void)
{
	/* log 파일 미사용시 생략 */
	if (!cfg_log_is_used()) {
		return;
	}

	fclose(log_file);
}

