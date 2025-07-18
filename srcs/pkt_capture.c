/**
@file pkt_capture.c
@author 남태일(taeil.nam@monitorapp.com)
@date 2025-07-17
@brief 패킷 캡처 관련 코드 
*/

#include <pcap.h>
#include "cfg.h"
#include "log.h"
#include "pkt_capture.h"

/*
********************************************************************************
* DATA TYPES
********************************************************************************
*/

/*
********************************************************************************
* VARIABLES
********************************************************************************
*/
static char *net_if; /**< 패킷을 캡처할 네트워크 인터페이스 */
static char err_buf[PCAP_ERRBUF_SIZE]; /**< PCAP 관련 에러 메시지 buffer */

/*
********************************************************************************
* PROTOTYPES
********************************************************************************
*/

/**
@brief pkt_capture 함수

패킷 캡처 로직 수행

@param void
@return void
*/
void pkt_capture(void)
{
	//pkt_net_if_set();
	/* test code start */
	(void)net_if; // dump code
	(void)err_buf; // dump code
	LOG(INFO, "PCAP_ERRBUF_SIZE = %dbytes.", PCAP_ERRBUF_SIZE);
	LOG(INFO, "BUFSIZ = %dbytes.", BUFSIZ);

	/* 3초마다 conf 파일 수정 여부 검사 및 재 파싱 예제 코드 */
	/*
	while (1) {
		LOG(INFO, "cfg_is_modified=%d.", cfg_file_is_modified());
		sleep(3);

		if (cfg_file_is_modified()) {
			cfg_free();
			cfg_parse();
			cfg_print();
		}
	}
	*/
	/* test code end */
}
/*
static void pkt_net_if_set(void)
{
	//TODO
}
*/
