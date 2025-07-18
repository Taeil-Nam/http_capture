/**
@file dump.h
@author 남태일(taeil.nam@monitorapp.com)
@date 2025-07-17
@brief dump 관련 헤더파일
*/

#ifndef DUMP_H 
#define DUMP_H

#include <stdio.h>
#include "cfg.h"

/*
********************************************************************************
* MACROS
********************************************************************************
*/
#define DUMP(fmt, ...)  dump_wr(fmt, ##__VA_ARGS__)

/*
********************************************************************************
* PROTOTYPES
********************************************************************************
*/
void dump_file_open(void);
void dump_wr(const char *fmt, ...);
void dump_file_close(void);

#endif
