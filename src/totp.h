/*    totp.h    */

/*
 * Author   : ripmeep
 * GitHub   : https://github.com/ripmeep/
 * Instagram: @pete.meep
 * Date     : 22/12/2023
 */

/* A lightweight and simple implementation for the TOTP algorithm
 * to generate secrets, and calculate codes. */

/*    MACROS & CONSTS    */
#ifndef _TOTP_H_

#define _GNU_SOURCE

#define TOTP_SECRET_LENGTH		16
#define TOTP_CODE_LENGTH		6
#define TOTP_TIME				30
#define TOTP_BASE32_CHARSET		"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

/*    INCLUDES    */
#include <stdint.h>

/*    TYPE DEFINITIONS    */
typedef struct __stotp
{
	char			secret[TOTP_SECRET_LENGTH + 1];
	char*			qr_url;
	char*			otpauth_url;
} stotp_t;

typedef struct __totp
{
	char		strcode[TOTP_CODE_LENGTH + 1];
	uint32_t	code;
	uint8_t		time;
} totp_t;

/*    FUNCTION DECLARATIONS    */
uint32_t totp_base32_decode(const char* __restrict__ src,
                            char* __restrict__ md,
                            int32_t len);

int32_t totp_strindexof(char* str, char c);
uint32_t totp_strtoupper(char* str);
struct __stotp* stotp_new(const char* __restrict__ secret);

void stotp_url_generate(struct __stotp* stotp,
						const char* issuer,
						const char* account);

struct __stotp* stotp_generate();
struct __totp* totp_now(struct __stotp* __restrict__ stotp);

#define _TOTP_H
#endif
