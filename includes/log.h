/**
@file log.h
@author 남태일(taeil.nam@monitorapp.com)
@date 2025-07-17
@brief log 관련 헤더파일
*/

#ifndef LOG_H 
#define LOG_H

#include <stdio.h>
#include "cfg.h"

/*
********************************************************************************
* CONSTANTS 
********************************************************************************
*/
#define INFO "INFOMATION"
#define WARN "WARNING"
#define ERR "ERROR"

/*
********************************************************************************
* MACROS
********************************************************************************
*/
#define LOG(level, fmt, ...)  log_write(level, __func__, fmt, ##__VA_ARGS__)

/*
********************************************************************************
* EXTERNALS 
********************************************************************************
*/
extern FILE *g_log_file; /**< log 파일 전역 변수 */

/*
********************************************************************************
* PROTOTYPES
********************************************************************************
*/
void log_file_open(void);
void log_write(const char *level, const char *func, const char *fmt, ...);
void log_file_close(void);

#endif
