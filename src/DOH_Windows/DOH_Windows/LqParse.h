/*
* Lanq(Lan Quick)
* Solodov A. N. (hotSAN)
* 2016
*/

#pragma once

#include <stdint.h>

typedef enum LqHttpPrsUrlStatEnm
{
	LQPRS_URL_SUCCESS,
	LQPRS_URL_ERR_SYMBOLIC_HOST_NAME,
	LQPRS_URL_ERR_IPv6_HOST_NAME,
	LQPRS_URL_ERR_USER_INFO,
	LQPRS_URL_ERR_PORT,
	LQPRS_URL_ERR_DIR,
	LQPRS_URL_ERR_QUERY,
} LqHttpPrsUrlStatEnm;

LqHttpPrsUrlStatEnm LqHttpPrsUrl
(
	char* String,
	char** SchemeStart, char** SchemeEnd,
	char** UserInfoStart, char** UserInfoEnd,
	char** HostStart, char** HostEnd,
	char** PortStart, char** PortEnd,
	char** DirStart, char** DirEnd,
	char** QueryStart, char** QueryEnd,
	char** FragmentStart, char** FragmentEnd,
	char** End, char* TypeHost,
	void(*AddQueryProc)(void* UserData, char* StartKey, char* EndKey, char* StartVal, char* EndVal),
	void* UserData
);

int LqDataToBase64(bool isUrl, bool AddEq, uint8_t* SrcData, size_t SrcDataSize, char* DestStr, size_t DestStrSize);

