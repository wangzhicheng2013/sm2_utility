gcc -g -o Test test_sm2.c sm2_utility.c -I ./ -I ./include/ -L ./ libcrypto.a -ldl -pthread  
gcc -g -o sm2_utility sm2_main.c sm2_utility.c -I ./ -I ./include/ -L ./ libcrypto.a -ldl -pthread  
