# ctotp
A lightweight TOTP library &amp; generator for C/C++

# Dependencies
OpenSSL
`sudo apt-get update && sudo apt-get install libssl-dev`

# Download & examples
```
git clone https://github.com/ripmeep/ctotp/ && cd ctotp
chmod +x build_example.sh
./build_examples.sh
```

# Generate a new TOTP secret which works with Google Authenticator
```
cd bin
./gen_secret Company Username

Issuer     : Company
Account    : Username
Secret     : V3SGFOVLHAWOSNHX
Raw backup : otpauth://totp/Company%3A%20Username?secret=V3SGFOVLHAWOSNHX
QR Code URL: https://chart.apis.google.com/chart?cht=qr&chs=200x200&chl=otpauth%3A%2F%2Ftotp%2FUsername%3Fsecret%3DV3SGFOVLHAWOSNHX%26issuer%3DCompany
```

# Generate a TOTP code with the above example
```
./gen_totp V3SGFOVLHAWOSNHX

OTP Code      : 235084
Time Remaining: 10s
```

# Generate a pretty output example for the TOTP above
![time_green](https://github.com/ripmeep/ctotp/assets/36815692/dafdca37-8df0-416a-91c9-9b8bef9a488d)
![time_red](https://github.com/ripmeep/ctotp/assets/36815692/a864b0d2-e76e-4994-b4a9-3c1d22f843a1)
