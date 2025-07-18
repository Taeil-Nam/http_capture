/**
@file main.c
@author 남태일(taeil.nam@monitorapp.com)
@date 2025-07-15
@brief http_capture 프로그램의 시작
*/

/**
@mainpage http 패킷 캡처 프로그램

@section intro 소개
이 프로젝트는 간단한 http 패킷 캡처 프로그램 예제이다.

@section developer 개발자
남태일(taeil.nam@monitorapp.com)

@section history 역사
2025-07-15: 프로젝트 시작

@section requirment 요구 사항
우분투 환경
libpcap 라이브러리
*/

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <syslog.h>
#include "cfg.h"
#include "log.h"
#include "dump.h"
#include "pkt_capture.h"

/*
********************************************************************************
* PROTOTYPES
********************************************************************************
*/
static void init(void);
static void run(void);
static void cleanup(void);
static void process_demonize(void);

/**
@brief main 함수

프로그램의 시작 코드

@param void
@return 성공시 0 반환, 오류 발생시 1 반환
*/
int main(void)
{
	init();
	run();
	cleanup();

	return 0;
}

/**
@brief init 정적 함수

프로그램 초기 설정

@param void
@return void
*/
static void init(void)
{
	/* 데몬 프로세스로 변환 */
	process_demonize();

	/* syslog 시작 */
	openlog(NULL, LOG_PID | LOG_NDELAY, LOG_DAEMON);
	syslog(LOG_INFO, "daemon started.");

	/* conf 파일 파싱 */
	cfg_parse();

	/* log 파일 생성 */
	log_file_open();

	/* dump 파일 생성 */
	dump_file_open();
}

/**
@brief run 정적 함수

프로그램 main 로직

@param void
@return void
*/
static void run(void)
{
	syslog(LOG_INFO, "===STARTED PACKET CAPTURE===");
	LOG(INFO, "===STARTED PACKET CAPTURE===");
	pkt_capture();
}

/**
@brief cleanup 정적 함수

프로그램 종료 전, 사용된 자원 반납

@param void
@return void
*/
static void cleanup(void)
{
	closelog(); // syslog 종료
	log_file_close();
	dump_file_close();
	cfg_free();
}

/**
@brief process_demonize 정적 함수

현재 프로세스를 데몬 프로세스로 변환

@param void
@return void
*/
static void process_demonize(void)
{
	pid_t pid;

	/* 백그라운드로 실행 */
	pid = fork();
	if (pid < 0) {
		exit(EXIT_FAILURE);
	} else if (pid > 0) {
		exit(EXIT_SUCCESS);
	}

	/* 터미널과 분리 */
	if (setsid() < 0) {
		exit(EXIT_FAILURE);
	}

	/* 시그널 무시 */
	signal(SIGCHLD, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	/* 터미널 분리 보장 */
	pid = fork();
	if (pid < 0) {
		exit(EXIT_FAILURE);
	} else if (pid > 0) {
		exit(EXIT_SUCCESS);
	}

	/* 기본 파일 생성 권한 설정 */
	umask(0);

	/* 작업 디렉토리 변경 */
	chdir("/");

	/* 모든 fd close */
	for (long fd = sysconf(_SC_OPEN_MAX); fd >= 0; fd--) {
		close(fd);
	}
}

