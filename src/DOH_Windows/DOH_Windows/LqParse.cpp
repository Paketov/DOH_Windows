/*
* Lanq(Lan Quick)
* Solodov A. N. (hotSAN)
* 2016
*/


#include "LqParse.h"
#include <windows.h>
#include <stdint.h>

#define IS_ENG_ALPHA(c) ((*(c) >= 'a') && (*(c) <= 'z') || (*(c) >= 'A') && (*(c) <= 'Z'))
#define IS_DIGIT(c)  ((*(c) >= '0') && (*(c) <= '9'))
#define IS_HEX(c) (IS_DIGIT(c) || (*(c) >= 'A') && (*(c) <= 'F') || (*(c) >= 'a') && (*(c) <= 'f'))

#define IS_RESERVED(c) (\
    (*(c) == ';') || (*(c) == '/') || \
    (*(c) == '?') || (*(c) == ':') || \
    (*(c) == '@') || (*(c) == '&') || \
    (*(c) == '=') || (*(c) == '+') || \
    (*(c) == '$') || (*(c) == ',') || \
    (*(c) == '#'))

bool LqStrCharUtf16IsAlpha(uint32_t r) {
	return IsCharAlphaW(r) == TRUE;
}


uint32_t LqStrUtf8toUtf16(const char **s, size_t Size) {
	uint32_t CodePoint = 0;
	int Fol = 0;
	for (const char* m = *s + Size; *s < m; ) {
		unsigned char ch = *(unsigned char*)(*s);
		(*s)++;
		if (ch <= 0x7f) {
			CodePoint = ch;
			Fol = 0;
		}
		else if (ch <= 0xbf) {
			if (Fol > 0) {
				CodePoint = (CodePoint << 6) | (ch & 0x3f);
				--Fol;
			}
		}
		else if (ch <= 0xdf) {
			CodePoint = ch & 0x1f;
			Fol = 1;
		}
		else if (ch <= 0xef) {
			CodePoint = ch & 0x0f;
			Fol = 2;
		}
		else {
			CodePoint = ch & 0x07;
			Fol = 3;
		}
		if (Fol == 0) {
			if (CodePoint > 0xffff)
				return (uint32_t)(0xd800 + (CodePoint >> 10)) | ((0xdc00 + (CodePoint & 0x03ff)) << 16);
			else
				return CodePoint;
			CodePoint = 0;
		}
	}
	return (uint32_t)-1;
}

char* LqStrUtf8IsAlpha(const char* s1) {
	if ((unsigned char)*s1 < 128) {
		if ((*s1 >= 'A' && *s1 <= 'Z') || (*s1 >= 'a' && *s1 <= 'z'))
			return (char*)s1 + 1;
	}
	else {
		uint32_t ri = LqStrUtf8toUtf16(&s1, 4);
		if ((ri < 0x10ffff) && LqStrCharUtf16IsAlpha(ri))
			return (char*)s1;
	}
	return nullptr;
}

char* LqStrUtf8IsAlphaNum(const char* s1) {
	if ((unsigned char)*s1 < 128) {
		if ((*s1 >= 'A' && *s1 <= 'Z') || (*s1 >= 'a' && *s1 <= 'z') || (*s1 >= '0' && *s1 <= '9'))
			return (char*)s1 + 1;
	}
	else {
		uint32_t ri = LqStrUtf8toUtf16(&s1, 4);
		if ((ri < 0x10ffff) && LqStrCharUtf16IsAlpha(ri))
			return (char*)s1;
	}
	return nullptr;
}

static char* IS_UNRESERVED(const char* c) {
	if ((*(c) == '-') ||
		(*(c) == '.') || (*(c) == '_') ||
		(*(c) == '~') || (*(c) == '!') ||
		(*(c) == '*') || (*(c) == '\'') ||
		(*(c) == '(') || (*(c) == ')'))
		return (char*)c + 1;
	return LqStrUtf8IsAlphaNum(c);
}


static char* IS_ESCAPE(const char* c) {
	if ((*c == '%') && IS_HEX(c + 1) && IS_HEX(c + 2))
		return (char*)c + 3;
	return nullptr;
}

static char* IS_USER_INFO(const char* c) {
	if (auto r = IS_UNRESERVED(c))
		return r;
	if (auto r = IS_ESCAPE(c))
		return r;
	if ((*(c) == ';') || (*(c) == ':') ||
		(*(c) == '&') || (*(c) == '=') ||
		(*(c) == '+') || (*(c) == '$') ||
		(*(c) == ','))
		return (char*)c + 1;
	return nullptr;
}


static char* IS_PCHAR(const char* c) {
	if (auto r = IS_UNRESERVED(c))
		return r;
	if (auto r = IS_ESCAPE(c))
		return r;
	if ((*(c) == ':') || (*(c) == '@') ||
		(*(c) == '&') || (*(c) == '=') ||
		(*(c) == '+') || (*(c) == '$') ||
		(*(c) == ','))
		return (char*)c + 1;
	return nullptr;
}

static char* IS_DIR(const char* c) {
	if ((*c == '/') || (*c == ';'))
		return (char*)c + 1;
	if (auto r = IS_PCHAR(c))
		return r;
	return nullptr;
}

static char* IS_URIC_WITHOUT_EQ_AMP(const char* c) {
	if (auto r = IS_UNRESERVED(c))
		return r;
	if (auto r = IS_ESCAPE(c))
		return r;
	if ((*(c) == ';') || (*(c) == '/') ||
		(*(c) == '?') || (*(c) == ':') ||
		(*(c) == '@') || (*(c) == '+') ||
		(*(c) == '$') || (*(c) == ','))
		return (char*)c + 1;
	return nullptr;
}

static char* IS_URIC(const char* c) {
	if (auto r = IS_UNRESERVED(c))
		return r;
	if (auto r = IS_ESCAPE(c))
		return r;
	if (IS_RESERVED(c))
		return (char*)c + 1;
	return nullptr;
}



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
	) {
	/*
	Based on RFC 3987 https://www.ietf.org/rfc/rfc3987.txt
	*/

	char* c = String, *t,
		*StartScheme = nullptr, *EndScheme = nullptr,
		*StartUserInfo = nullptr, *EndUserInfo = nullptr,
		*StartHost = nullptr, *EndHost = nullptr,
		*StartPort = nullptr, *EndPort = nullptr,
		*StartDir = nullptr, *EndDir = nullptr,
		*StartQuery = nullptr, *EndQuery = nullptr,
		*StartFragment = nullptr, *EndFragment = nullptr,
		HostType = ' ';
	for (; (*c == ' ') || (*c == '\t'); c++);
	t = c;
	/*Read scheme*/
	if (IS_ENG_ALPHA(c)) {
		for (; IS_ENG_ALPHA(c) || IS_DIGIT(c) || (*c == '.') || (*c == '+') || (*c == '-'); c++);
		if ((c[0] == ':') && (c[1] == '/') && (c[2] == '/')) {
			StartScheme = t;
			EndScheme = c;
			c += 3;
		}
		else
			c = t;
	}
	/*Read user info*/
	t = c;
	for (; auto r = IS_USER_INFO(c); c = r);
	if ((*c == '@') && (c != t)) {
		StartUserInfo = t;
		EndUserInfo = c;
		c++;
	}
	else
		c = t;
	t = c;
	/*Parse host name*/
	if (IS_DIGIT(c)) {
		/*Read IPv4 host name*/
		for (unsigned i = 0; ; i++) {
			unsigned d = 0;
			for (char* m = c + 3; IS_DIGIT(c) && (c < m); c++)
				d = d * 10 + (*c - '0');
			if (d > 255) goto lblHostName;
			if (i >= 3) break;
			if (*c != '.') goto lblHostName;
			c++;
		}
		StartHost = t;
		EndHost = t = c;
		HostType = '4';
		goto lblPort;
	}
lblHostName:
	c = t;
	if (LqStrUtf8IsAlpha(c)) {
		/*Read symbolic host name*/
	lblRep:

		for (char* r;;) {
			if ((r = LqStrUtf8IsAlphaNum(c)) != nullptr)
				c = r;
			else if (*c == '-')
				c++;
			else
				break;

		}
		if (*(c - 1) == '-')
			return LQPRS_URL_ERR_SYMBOLIC_HOST_NAME;
		if ((*c == '.') && (LqStrUtf8IsAlphaNum(c + 1) != nullptr)) {
			c++;
			goto lblRep;
		}
		else {
			StartHost = t;
			EndHost = c;
			HostType = 's';
			goto lblPort;
		}
	}
	else if (*c == '[') {
		/*Read IPv6 host name*/
		c++;
		unsigned Count = 0;
		bool IsHaveReduct = false;
		if (*c == ':') {
			if (c[1] == ':') {
				c += 2;
				IsHaveReduct = true;
				if (*c == ']') goto lblIPv6Continue;
			}
			else
				return LQPRS_URL_ERR_IPv6_HOST_NAME;
		}
		while (true) {
			if (IS_HEX(c)) {
				Count++;
				char* t = c++;
				for (; IS_HEX(c); c++);
				if (c > (t + 4)) return LQPRS_URL_ERR_IPv6_HOST_NAME;
				if (*c == ':') {
					c++;
					if (*c == ':') {
						if (IsHaveReduct)
							return LQPRS_URL_ERR_IPv6_HOST_NAME;
						IsHaveReduct = true;
						c++;
						if (*c == ']')
							break;
					}
					else if (!IS_HEX(c))
						return LQPRS_URL_ERR_IPv6_HOST_NAME;
				}
				else if (*c == ']')
					break;
				else
					return LQPRS_URL_ERR_IPv6_HOST_NAME;
			}
			else
				return LQPRS_URL_ERR_IPv6_HOST_NAME;
		}
	lblIPv6Continue:
		if (IsHaveReduct) {
			if (Count >= 8)
				return LQPRS_URL_ERR_IPv6_HOST_NAME;
		}
		else if (Count < 8)
			return LQPRS_URL_ERR_IPv6_HOST_NAME;
		StartHost = t;
		EndHost = t = ++c;
		HostType = '6';
		goto lblPort;
	}
	else if (StartUserInfo != nullptr)
		return LQPRS_URL_ERR_USER_INFO;

	goto lblDir;
lblPort:
	/*Read port*/
	t = c;
	if (*c == ':') {
		c++;
		unsigned d = 0;
		for (char* m = c + 5; IS_DIGIT(c) && (c < m); c++)
			d = d * 10 + (*c - '0');
		if (d > 65535) return LQPRS_URL_ERR_PORT;
		StartPort = t + 1;
		EndPort = c;
	}
lblDir:
	t = c;
	/*Read directory*/
	if (*c == '/') {
		for (; auto r = IS_DIR(c); c = r);
		StartDir = t;
		EndDir = t = c;
	}
	else
		return LQPRS_URL_ERR_DIR;
	/*Read query*/
	if (*c == '?') {
		char ForEmptyArg = '\0';
		for (char *StartKey, *EndKey, *StartVal, *EndVal;;) {
			c++;
			StartKey = c;
			for (; auto r = IS_URIC_WITHOUT_EQ_AMP(c); c = r);
			if ((EndKey = c) == StartKey) return LQPRS_URL_ERR_QUERY;
			if (*c == '=') {
				StartVal = ++c;
				for (; auto r = IS_URIC_WITHOUT_EQ_AMP(c); c = r);
				EndVal = c;
			}
			else {
				EndVal = StartVal = &ForEmptyArg;
			}
			if (AddQueryProc != NULL)
				AddQueryProc(UserData, StartKey, EndKey, StartVal, EndVal);
			if (*c != '&')
				break;
		}
		StartQuery = t + 1;
		EndQuery = t = c;
	}
	/*Read fragment*/
	if (*c == '#') {
		c++;
		for (; auto r = IS_URIC(c); c = r);
		StartFragment = t;
		EndFragment = t = c;
	}

	*SchemeStart = StartScheme; *SchemeEnd = EndScheme;
	*UserInfoStart = StartUserInfo; *UserInfoEnd = EndUserInfo;
	*HostStart = StartHost;  *HostEnd = EndHost;
	*PortStart = StartPort; *PortEnd = EndPort;
	*DirStart = StartDir; *DirEnd = EndDir;
	*QueryStart = StartQuery; *QueryEnd = EndQuery;
	*FragmentStart = StartFragment; *FragmentEnd = EndFragment;
	*End = t;
	*TypeHost = HostType;
	return LQPRS_URL_SUCCESS;
}


static const unsigned char CodeChainBase64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const unsigned char CodeChainBase64URL[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"; //-_-

int LqDataToBase64(bool isUrl, bool AddEq, uint8_t* SrcData, size_t SrcDataSize, char* DestStr, size_t DestStrSize) {
	int Written = 0;
	const unsigned char *CodeChain = (isUrl) ? CodeChainBase64URL : CodeChainBase64;
	const unsigned char *s = (const unsigned char*)SrcData;
	size_t MaxDataSize = (DestStrSize / 4) * 3;
	const unsigned char *sm = s + min(SrcDataSize, MaxDataSize);
	unsigned char *d = (unsigned char*)DestStr;

	while ((sm - s) > 2) {
		*d++ = CodeChain[(s[0] >> 2) & 0x3f];
		*d++ = CodeChain[((s[0] & 3) << 4) | (s[1] >> 4)];
		*d++ = CodeChain[((s[1] & 0x0f) << 2) | (s[2] >> 6)];
		*d++ = CodeChain[s[2] & 0x3f];
		s += 3;
	}
	if ((sm - s) > 0) {
		*d++ = CodeChain[(s[0] >> 2) & 0x3f];
		if ((sm - s) == 1) {
			*d++ = CodeChain[(s[0] & 3) << 4];
			if (AddEq) *d++ = '=';
		}
		else {
			*d++ = CodeChain[((s[0] & 3) << 4) | (s[1] >> 4)];
			*d++ = CodeChain[(s[1] & 0x0f) << 2];
		}
		if (AddEq) *d++ = '=';
	}
	*d = '\0';
	return d - (unsigned char*)DestStr;
}