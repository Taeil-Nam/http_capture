/**
@file cfg_parse.c
@author 남태일(taeil.nam@monitorapp.com)
@date 2025-07-15
@brief conf 파일 파싱 코드 
*/
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "cfg_parse.h"

/**
@brief cfg_parse 함수
conf 파일 파싱 후, 각 라인의 key, value 값을 각 cfg_entry_t 구조체에 저장

@param cfg_entry_t 구조체의 배열 
@return void
*/
void cfg_parse(cfg_entry_t *cfg_entries)
{
	int g_cfg_entry_cnts = 0;
	int cfg_fd;

	// TODO: conf 파일(KEY=VALUE) 파싱 구현
	cfg_file_fd = open(CFG_FILE_PATH, O_RDONLY, 0644);
	cfg_test_file_fd = open(CFG_PARSE_TEST_PATH, O_WDONLY | O_CREAT | O_TRUNC, 0644);

	/* test code */
	(void)g_cfg_entry_cnts;
	(void)cfg_entries;
	write(cfg_test_file_fd, "taeil\n", 6);
}

