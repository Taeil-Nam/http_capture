/**
@file main.c
@author 남태일(taeil.nam@monitorapp.com)
@date 2025-07-15
@brief http_capture 프로그램의 시작

main 함수부터 프로그램 시작.
프로세스를 데몬 프로세스로 변경.
conf 파일 파싱.
log 파일 생성.
dump 파일 생성.
패킷 캡처 수행.
RESET 패킷 전송.
종료.
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

#include <stdbool.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "cfg_parse.h"

static void process_demonize(void);

/**
@brief main 함수
프로그램 시작 코드

@param void
@return 성공 여부
*/
int main(void)
{
	cfg_entry_t cfg_entries[MAX_PARSE_LINE];

	process_demonize();
	cfg_parse(cfg_entries);

	while (true){

	}

	return 0;
}

/**
@brief process_demonize 함수
현재 프로세스를 데몬 프로세스로 변환해주는 함수

@param void
@return void
*/
static void process_demonize(void)
{
	pid_t pid;

	/* 백그라운드로 실행 */
	pid = fork();
	if (pid < 0){
		exit(EXIT_FAILURE);
	} else if (pid > 0){
		exit(EXIT_SUCCESS);
	}

	/* 터미널과 분리 */
	if (setsid() < 0){
		exit(EXIT_FAILURE);
	}

	/* 시그널 무시 */
	signal(SIGCHLD, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	/* 터미널 분리 보장 */
	pid = fork();
	if (pid < 0){
		exit(EXIT_FAILURE);
	} else if (pid > 0){
		exit(EXIT_SUCCESS);
	}

	/* 기본 파일 생성 권한 설정 */
	umask(0);

	/* 작업 디렉토리 변경 */
	chdir("/");

	/* 모든 fd close */
	for (long fd = sysconf(_SC_OPEN_MAX); fd >= 0; fd--){
		close(fd);
	}
}

