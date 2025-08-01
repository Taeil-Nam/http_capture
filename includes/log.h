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
#define INFO "INFO" /**< log level = information */
#define WARN "WARNING" /**< log level = warning */
#define ERR "ERROR"/**< log level = error */

/*
********************************************************************************
* MACROS
********************************************************************************
*/
#define LOG(level, fmt, ...) log_wr(level, fmt, ##__VA_ARGS__)

/*
********************************************************************************
* PROTOTYPES
********************************************************************************
*/
void log_file_open(void);
void log_wr(const char *level, const char *fmt, ...);
void log_file_close(void);

#endif

