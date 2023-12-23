/*    totp.h    */

/*
 * Author   : ripmeep
 * GitHub   : https://github.com/ripmeep/
 * Instagram: @pete.meep
 * Date     : 22/12/2023
 */

/* A lightweight and simple implementation for the TOTP algorithm
 * to generate secrets, and calculate codes. */

/*    INCLUDES    */
#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#ifndef _TOTP_H_
	#include "totp.h"
#endif

#ifndef NULL
	#define NULL (void*)0
#endif

/* FUNCTION DEFINITIONS */

/* Edited implementation of a base32 decode function from
   the following URL - (modified into 1 function):
   https://www.omarpolo.com/post/base32-decoder.html */
uint32_t totp_base32_decode(const char* __restrict__ src,
							char* md,
							int32_t len)
{
	int		v[8];
	char*	dst;

	dst = md;

	while (*src)
	{
		memset( v, 0, sizeof(v) );

		for (int i = 0; i < 8; i++)
		{
			if (*src == 0)
				break;

			if (*src >= 'A' && *src <= 'Z') /* Convert to uppercase if alpha */
				v[i] = (int)(*src - 'A');
			else if (*src >= '2' && *src <= '7') /* Convert to numerical if alphanum */
				v[i] = (int)(*src - '2' + 26);
			else
				return 0;

			*src++;
		}

		if (len <= 0)
			break;

		len -= 5;

		*dst++ = (v[0] << 3) | (v[1] >> 2);
		*dst++ = ((v[1] & 0x03) << 6) | (v[2] << 1) | (v[3] >> 4);
		*dst++ = ((v[3] & 0x0F) << 4) | (v[4] >> 1);
		*dst++ = ((v[4] & 0x01) << 7) | (v[5] << 2) | (v[6] >> 3);
		*dst++ = ((v[6] & 0x07) << 5) | v[7];
	}

	return (dst - md);
}

/* Find index of base32 character */
int32_t totp_strindexof(char* str, char c)
{
	for (int32_t i = 0; i < (int32_t)strlen(str); i++)
	{
		if (str[i] == c)
			return i;
	}

	return -1;
}

/* Convert string to uppercase */
uint32_t totp_strtoupper(char* str)
{
	char*		c;
	uint32_t	szc;

	c   = str;
	szc = 0;

	while (*c)
	{
		if (isalpha(*c) && !isupper(*c))
			*c = toupper(*c + (szc++ - (szc - 1)));

		*c++;
	}

	return szc;
}

/* Create new seed TOTP structure from base32 secret */
struct __stotp* stotp_new(const char* __restrict__ secret)
{
	struct __stotp*		stotp;
	char*				usecret;

	stotp = malloc( sizeof(struct __stotp) + 1 );
	assert(stotp != NULL);
	memset( stotp, 0, sizeof(stotp) + 1 );

	usecret = strdup(secret);

	totp_strtoupper((char*)usecret);

	strncpy( stotp->secret, usecret, sizeof(stotp->secret) );

	return stotp;
}

/* Generate URLs and populate qr_url & otpauth_url structure fields */
void stotp_url_generate(struct __stotp* stotp,
						const char* issuer,
						const char* account)
{
	uint32_t			ul_url_len;

	ul_url_len = 64 + strlen(account);
	stotp->otpauth_url = malloc(ul_url_len);
	assert(stotp->otpauth_url != NULL);

	snprintf(stotp->otpauth_url,
			 ul_url_len,
			 "otpauth://totp/%s%%3A%%20%s?secret=%s",
			 issuer,
			 account,
			 stotp->secret);

	ul_url_len = 128 + strlen(stotp->otpauth_url);
	stotp->qr_url = malloc(ul_url_len);
	assert(stotp->qr_url != NULL);

	snprintf(stotp->qr_url,
			 ul_url_len,
			 "https://chart.apis.google.com/chart?cht=qr&chs=200x200&chl=otpauth%%3A%%2F%%2Ftotp%%2F%s%%3Fsecret%%3D%s%%26issuer%%3D%s",
			 account,
			 stotp->secret,
			 issuer);
}

/* Generate new random seed TOTP (secret) using OpenSSL rand bytes */
struct __stotp* stotp_generate()
{
	struct __stotp*		stotp;
	char				rng[16];

	stotp = malloc( sizeof(struct __stotp) + 1 );
	assert(stotp != NULL);
	memset( stotp, 0, sizeof(stotp) + 1 );

	RAND_bytes(rng, 16);

	for (int i = 0; i < sizeof(rng); i++)
		stotp->secret[i] = TOTP_BASE32_CHARSET[(uint8_t)rng[i] % 32];

	return stotp;
}

/* Calculate current TOTP code from time and secret using seed TOTP */
struct __totp* totp_now(struct __stotp* __restrict__ stotp)
{
	struct __totp*	totp;
	char			key[10];
	unsigned char	hash[20], code[4];
	uint32_t		ul_code, ul_hash_len, ul_time;
	uint64_t		ull_time;

	assert(stotp != NULL && stotp->secret != NULL);

	memset( key, 0, sizeof(key) );

	totp = malloc( sizeof(struct __totp) + 1 );
	assert(totp != NULL);
	memset( totp, 0, sizeof(struct __totp) + 1 );

	if (totp_base32_decode(stotp->secret, key, 10) < 10) /* Make sure 10 bytes are returned */
		return NULL;

	ul_time  = time(NULL); /* Time as 32 bit unsigned integer (used for time remaining calc with epoch) */
	ull_time = (uint64_t)floor(ul_time / TOTP_TIME); /* Current HOTP count from epoch time */
	ull_time = (ull_time >> 56) | /* Convert to big endian */
			   ((ull_time << 40) & 0x00FF000000000000) |
			   ((ull_time << 24) & 0x0000FF0000000000) |
			   ((ull_time << 8)  & 0x000000FF00000000) |
			   ((ull_time >> 8)  & 0x00000000FF000000) |
			   ((ull_time >> 24) & 0x0000000000FF0000) |
			   ((ull_time >> 40) & 0x000000000000FF00) |
			   (ull_time << 56);

	ul_hash_len = 20;

	HMAC(EVP_sha1(), /* Calculate HMACSHA1(secret, time) */
		 key,
		 sizeof(key),
		 (unsigned char*)&ull_time,
		 sizeof(uint64_t),
		 hash,
		 &ul_hash_len);

	memset( code, 0, sizeof(code) );
	memcpy(code, hash + ((uint8_t)hash[19] & 15), 5); /* BAND last hash byte with 0xF */
	memcpy(&ul_code, code, 5); /* Interpret raw 5 bytes from BAND'd byte as 32 bit integer */

	ul_code = ((ul_code & 0x000000FF) << 24) | /* Convert to big endian */
			  ((ul_code & 0x0000FF00) << 8)  |
			  ((ul_code & 0x00FF0000) >> 8)  |
			  ((ul_code & 0xFF000000) >> 24);

	ul_code = (ul_code & 0x7FFFFFFF) % 1000000; /* Calculate OTP code */

	totp->code = ul_code;

	snprintf(totp->strcode, /* strcode member shown with padded 0s */
			 sizeof(totp->strcode),
			 "%06ld",
			 ul_code);

	totp->time = (TOTP_TIME - (ul_time % TOTP_TIME)); /* Populate time remaining on current code */

	return totp;
}
