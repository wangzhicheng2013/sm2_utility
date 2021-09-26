gcc -g -o sm2_utility sm2_main.c sm2_utility.c -I ./ -I ./include/ -L ./ libcrypto.a -ldl -pthread  
gcc -g -o mock_sm2 mock_sm2.c  -I ./ -I ./include/ -L ./ libcrypto.a -ldl -pthread  