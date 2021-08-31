# anonymous_broadcast_authentication

## Overview
This repository is a simple implementation of an anonymous broadcast authentication (ABA) scheme. 

## Install Instruction
We implemented ABA by utilizing **gcc 7.5.0** and **OpenSSL 1.1.1** on Ubuntu 18.04.5 LTS with Windows Subsyste for Linux. 
You may need to install **libssl-dev 1.1.1**. 

### List of Files
1. `aba-strong.c` scheme with the strong anonymity. 
2. `aba-weak.c` scheme with the weak anonymity. 
3. `aba-strong_wocounter.c` scheme with the strong anonymity (but not including a counter). 
4. `aba-weak_wocounter.c` scheme with the weak anonymity (but not including a counter). 

### Execute ABA
1. Create clone of ABA onto your local.
2. Type `gcc aba-weak.c -lcrypto -lm` on `aba-weak.c` or `aba-weak_wocounter.c`
3. Or `gcc aba-strong.c -lcrypto` on `aba-strong.c` or `aba-strong_wocounter.c`
4. Run an executable file output by gcc

## License
This project is distributed under the Apache License Version 2.0. Please refer to LICENSE.txt for details.

## Acknowledgement
This code was developed under a contract of Research and development on IoT malware removal / make it non-functional technologies for effective use of the radio spectrum among Research and Development for Expansion of Radio Wave Resources (JPJ000254), which was supported by the Ministry of Internal Affairs and Communications, Japan.
