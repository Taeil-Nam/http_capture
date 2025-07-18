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
@brief pkt_capture_setup 함수

패킷 캡처 관련 초기 설정 로직 수행

@param void
@return void
*/
void pkt_capture_setup(void)
{
	/* log 파일 생성 */
	log_file_open();
	LOG(INFO, "hello~");
	(void)net_if; //dummy code
	(void)err_buf;//dummy code
}
