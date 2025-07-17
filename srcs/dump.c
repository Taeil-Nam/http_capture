/**
@file dump.c
@author 남태일(taeil.nam@monitorapp.com)
@date 2025-07-17
@brief dump 관련 코드 
*/

#include <stdarg.h>
#include <stdlib.h>
#include <time.h>
#include "log.h"
#include "dump.h"

/*
********************************************************************************
* DATA TYPES
********************************************************************************
*/
FILE *g_dump_file = NULL;

/**
@brief dump_file_open 함수

conf 파일에서 dump 파일 경로를 찾고, 해당 경로에 dump 파일을 생성
dump 파일은 append 모드, 즉시 출력 모드로 생성
dump 파일 관련 설정이 없거나, dump 파일 생성 실패시 프로그램 종료

@param void
@return void 
*/
void dump_file_open(void)
{
	const char *dump_file_path = NULL;

	/* conf 파일에서 dump 파일 경로 찾기 */
	dump_file_path = cfg_val_find(CFG_DUMP_FILE_PATH);
	if (!dump_file_path) {
		LOG(ERR, "Count't find \"%s\" in configuration file.",
				CFG_DUMP_FILE_PATH);
		exit(EXIT_FAILURE);
	}
	
	/* dump 파일 생성 */
	g_dump_file = fopen(dump_file_path, "a");
	if (!g_dump_file) {
		LOG(ERR, "Failed to create dump file(%s).", dump_file_path);
		exit(EXIT_FAILURE);
	}

	/* 버퍼링 사용 없이 즉시 출력 */
	setvbuf(g_dump_file, NULL, _IONBF, 0);
}

/**
@brief dump_write 함수

dump 파일에 입력된 문자열 형식을 출력

@param fmt dump 문자열 형식
@param ... dump 문자열 형식에 포함된 가변 인자
@return void 
*/
void dump_write(const char *level, const char *fmt, ...)
{
	time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char time_buf[32];
    va_list args;

    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", t);

    fprintf(g_dump_file, "[%s] [%s] ", time_buf, level);
    va_start(args, fmt);
    vfprintf(g_dump_file, fmt, args);
    va_end(args);
    fprintf(g_dump_file, "\n");	
}

/**
@brief dump_file_close 함수

dump 파일 close

@param void
@return void 
*/
void dump_file_close(void)
{
	fclose(g_dump_file);
}

