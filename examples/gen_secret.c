#include <stdio.h>
#include "totp.h"

int main(int argc, char** argv)
{
	stotp_t*	stotp;

	if (argc < 3)
	{
		fprintf(stderr, "Usage: %s [ISSUER] [ACCOUNT NAME]\n", argv[0]);

		return 1;
	}

	stotp = stotp_generate();
	stotp_url_generate(stotp, argv[1], argv[2]);

	printf("Issuer     : %s\n", argv[1]);
	printf("Account    : %s\n", argv[2]);
	printf("Secret     : %s\n", stotp->secret);
	printf("Raw backup : %s\n", stotp->otpauth_url);
	printf("QR Code URL: %s\n", stotp->qr_url);

	return 0;
}
