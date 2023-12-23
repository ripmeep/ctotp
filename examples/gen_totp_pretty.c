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

	printf("\033[?25l");

	stotp = stotp_new(argv[1]);

	while (1)
	{
		totp = totp_now(stotp);

		printf("\r%s  %s", totp->strcode, totp->time <= 10 ? "\033[01;31m" : "\033[01;32m");

		for (int i = 0; i < totp->time; i++)
			printf("=");

		for (int i = 0; i < (32 - totp->time); i++)
			putchar(' ');

		printf("\033[0m%02ds", totp->time);

		fflush(stdout);
	}

	return 0;
}
