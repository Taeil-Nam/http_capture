/**
@file main.c
@author 남태일(taeil.nam@monitorapp.com)
@date 2025-07-15
@brief http_capture 프로그램의 시작
*/

/**
@mainpage http 패킷 캡처 프로그램

@section intro
이 프로젝트는 간단한 http 패킷 캡처 프로그램 예제이다

@section developer
남태일(taeil.nam@monitorapp.com)

@section history
2025-07-15: 프로젝트 시작

@section requirment
우분투 환경
libpcap 라이브러리
*/

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include "cfg.h"
#include "log.h"
#include "pkt_capture.h"
/*
********************************************************************************
* VARIABLES
********************************************************************************
*/
static bool is_running = true;

/*
********************************************************************************
* PROTOTYPES
********************************************************************************
*/
static void init(void);
static void run(void);
static void cleanup(void);
static void process_demonize(void);
static void sigterm_handler(int signum);

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
	/* conf 설정 적용 */
	cfg_apply();
	/* 패킷 캡처 관련 설정 */
	if (pkt_capture_setup() == -1) {
		cleanup();
		syslog(LOG_INFO, "daemon terminated.");
		exit(EXIT_FAILURE);
	}
}

/**
@brief run 정적 함수

프로그램의 main 로직을 수행
실시간으로 패킷 캡처(Non-blocking)
CFG_INTERVAL 마다 conf 파일 수정 유무 확인
conf 파일 수정 시, 수정된 설정 적용 후 다시 캡처

@param void
@return void
*/
static void run(void)
{
	struct timespec start_time, cur_time;
	int elapsed_time = 0;

	syslog(LOG_INFO, "Packet capture...[START]");
	clock_gettime(CLOCK_MONOTONIC, &start_time);
	while (is_running) {
		/* 패킷 캡처 */
		if (pkt_capture() == -1) {
			break;
		}
		clock_gettime(CLOCK_MONOTONIC, &cur_time);
		elapsed_time = cur_time.tv_sec - start_time.tv_sec;
		/* CFG_INTERVAL 마다 conf 수정 유무 확인 */
		if (elapsed_time >= cfg_interval_get()) {
			if (cfg_file_is_modified()) {
				syslog(LOG_INFO, "Packet capture...[DONE]");
				syslog(LOG_INFO, "Contiguration file modified.");
				cfg_apply();
				if (pkt_capture_setup() == -1) {
					break;
				}
				syslog(LOG_INFO, "Packet capture...[START]");
			}
			start_time = cur_time;
		}
		usleep(100);
	}
	syslog(LOG_INFO, "Packet capture...[DONE]");
}

/**
@brief cleanup 정적 함수

프로그램 종료 전, 사용된 자원 반납

@param void
@return void
*/
static void cleanup(void)
{
	syslog(LOG_INFO, "Cleanup resources...[START]");
	cfg_free();
	pkt_capture_free();
	syslog(LOG_INFO, "Cleanup resources...[DONE]");
	syslog(LOG_INFO, "daemon terminated.");
	closelog();
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
	/* KILL 시그널(SIGTERM) 핸들러 등록 */
	signal(SIGTERM, sigterm_handler);
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
	for (int fd = sysconf(_SC_OPEN_MAX); fd >= 0; fd--) {
		close(fd);
	}
}

/**
@brief sigterm_handler 정적 함수

kill 시그널(sigterm)을 받은 경우 호출됨
is_running = false로 설정하여 프로세스를 종료

@param int signal 번호(15)
@return void
*/
static void sigterm_handler(int signum)
{
	syslog(LOG_INFO, "SIGTERM(%d) Received", signum);
	is_running = false;
}
