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
#define INFO "INFO"
#define WARN "WARNING"
#define ERR "ERROR"

/*
********************************************************************************
* MACROS
********************************************************************************
*/
#define LOG(level, fmt, ...) \
	log_wr(level, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

/*
********************************************************************************
* PROTOTYPES
********************************************************************************
*/
void log_file_open(void);
void log_wr(const char *level, const char *file,
		int line, const char *fmt, ...);
void log_file_close(void);

#endif
