# anonymous_broadcast_authentication

## Overview
This repository is a simple implementation of an anonymous broadcast authentication (ABA) scheme. 

## Install Instruction
We implemented ABA by utilizing **gcc 7.5.0** and **OpenSSL 1.1.1** on Ubuntu 18.04.5 LTS with Windows Subsyste for Linux. 
You may need to install **libssl-dev 1.1.1**. 

### List of Files
1. `aba-test_join-simple.c` scheme with the strong anonymity. 
2. `aba-test_weak.c` scheme with the weak anonymity. 

### Execute ABA
1. Create clone of ABA onto your local.
2. Type `gcc aba-test_weak.c -lcrypto` or `gcc aba-test_join-simple.c -lcrypto`
3. Run an executable file output by gcc

## License
This project is distributed under the Apache License Version 2.0. Please refer to LICENSE.txt for details.
