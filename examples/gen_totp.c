#include <stdio.h>
#include "totp.h"

int main(int argc, char** argv)
{
	stotp_t*	stotp;
	totp_t*		totp;

	if (argc < 2)
	{
		fprintf(stderr, "Usage: %s [SECRET]\n", argv[0]);

		return 1;
	}

	stotp = stotp_new(argv[1]);
	totp  = totp_now(stotp);

	printf("OTP Code      : %s\n", totp->strcode);
	printf("Time Remaining: %02ds\n", totp->time);

	return 0;
}
