/**
@file dump.c
@author 남태일(taeil.nam@monitorapp.com)
@date 2025-07-17
@brief dump 관련 코드 
*/

#include <stdarg.h>
#include <stdlib.h>
#include <syslog.h>
#include <time.h>
#include "dump.h"

/*
********************************************************************************
* DATA TYPES
********************************************************************************
*/
static FILE *dump_file = NULL;

/**
@brief dump_file_open 함수

conf 파일에 dump 파일 사용이 명시되어있는 경우(1) dump 파일 생성
dump 파일을 append 모드, 즉시 출력 모드로 생성
dump 파일 생성 실패시 프로그램 종료

@param void
@return void 
*/
void dump_file_open(void)
{
	/* dump 파일 미사용시 생략 */
	if (!cfg_dump_is_used()) {
		return;
	}

	/* dump 파일 생성 */
	dump_file = fopen(CFG_DUMP_FILE_PATH, "a");

	/* dump 파일 생성 실패시 프로그램 종료 */
	if (!dump_file) {
		syslog(LOG_ERR, "Failed to create dump file(%s).", CFG_DUMP_FILE_PATH);
		exit(EXIT_FAILURE);
	}

	/* 버퍼링 사용 없이 즉시 출력 */
	setvbuf(dump_file, NULL, _IONBF, 0);

	/* dump 파일 생성 알림 */
    syslog(LOG_INFO, "===DUMP FILE CREATED===");
	fputs("\n\n===NEW DUMP STARTED===\n", dump_file);
}

/**
@brief dump_wr 함수

dump 파일에 입력된 문자열 형식을 출력

@param fmt dump 문자열 형식
@param ... dump 문자열 형식에 포함된 가변 인자
@return void 
*/
void dump_wr(const char *fmt, ...)
{
	time_t now = time(NULL);
	struct tm *t = localtime(&now);
	char time_buf[32];
	va_list args;
	
	/* dump 파일 미사용시 생략 */
	if (!cfg_dump_is_used()) {
		return;
	}

	/* 시간을 주어진 문자열 형식으로 변환 */
	strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", t);
	
	/* dump 출력 */
	fprintf(dump_file, "[%s] ", time_buf);
	va_start(args, fmt);
	vfprintf(dump_file, fmt, args);
	va_end(args);
	fprintf(dump_file, "\n");	
}

/**
@brief dump_file_close 함수

dump 파일 close

@param void
@return void 
*/
void dump_file_close(void)
{
	/* dump 파일 미사용시 생략 */
	if (!cfg_dump_is_used()) {
		return;
	}

	fclose(dump_file);
}

