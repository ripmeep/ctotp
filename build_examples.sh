rm -rf bin && mkdir ./bin
gcc ./examples/gen_secret.c ./src/totp.c -I ./src/ -o ./bin/gen_secret -lcrypto && echo "Built 'gen_secret' -> './bin/gen_secret'"
gcc ./examples/gen_totp.c ./src/totp.c -I ./src/ -o ./bin/gen_totp -lcrypto && echo "Built 'gen_totp' -> './bin/gen_totp'"
gcc ./examples/gen_totp_pretty.c ./src/totp.c -I ./src/ -o ./bin/gen_totp_pretty -lcrypto && echo "Built 'gen_totp_pretty' -> './bin/gen_totp_pretty'"
