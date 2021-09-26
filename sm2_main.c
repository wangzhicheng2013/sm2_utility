// sm2工具主入口 接收命令行参数进行相关操作
// 加密:./sm2_utility --run_mode encypt_file --plain_file_path ./1.txt --ctext_file_path ./3.txt
// 解密:./sm2_utility --run_mode decypt_file --ctext_file_path ./3.txt --plain_file_path ./4.txt
#include <getopt.h>
#include "sm2_utility.h"
char *const short_options = "rpkcstmugh:";
char *l_opt_arg = NULL; 
struct option long_options[] = {  
     { "run_mode",            1,   NULL,    'r'     },
     { "plain_file_path",     1,   NULL,    'p'     },
     { "key_file_path",       1,   NULL,    'k'     },      
     { "ctext_file_path",     1,   NULL,    'c'     },
     { "string_hex_key",      1,   NULL,    's'     },      
     { "type_of_curve",       1,   NULL,    't'     },      
     { "message_file_path",   1,   NULL,    'm'     },      
     { "user_file_path",      1,   NULL,    'u'     },      
     { "sig_file_path",       1,   NULL,    'g'     }, 
     { "help",                0,   NULL,    'h'     },  
     {      0,                0,      0,     0      },  
};
void usage() {
    printf("sm2 encrypt:./sm2_utility --run_mode encypt_file --plain_file_path ./1.txt --ctext_file_path ./3.txt\n");
    printf("sm2 encrypt:./sm2_utility --run_mode encypt_file_with_key --plain_file_path ./1.txt --string_hex_key 0011aaaB --ctext_file_path ./3.txt\n");
    printf("sm2 encrypt:./sm2_utility --run_mode encypt_file_with_key --plain_file_path ./1.txt --string_hex_key 0011aaaB --ctext_file_path ./3.txt --type_of_curve 1172\n");
    printf("sm2 encrypt:./sm2_utility --run_mode encypt_file_with_key_file --plain_file_path ./1.txt --key_file_path ./2.txt --ctext_file_path ./3.txt\n");
    printf("sm2 encrypt:./sm2_utility --run_mode encypt_file_with_key_file --plain_file_path ./1.txt --key_file_path ./2.txt --ctext_file_path ./3.txt --type_of_curve 1172\n");
    printf("sm2 sign:./sm2_utility --run_mode sign_message --message_file_path ./1.txt --key_file_path ./2.txt --user_file_path ./3.txt --sig_file_path ./4.txt\n");

    printf("sm2 decrypt:./sm2_utility --run_mode decypt_file --ctext_file_path ./3.txt --plain_file_path ./4.txt\n");
    printf("sm2 decrypt:./sm2_utility --run_mode decypt_file_with_key --ctext_file_path ./3.txt --string_hex_key 0011aaaB --plain_file_path ./1.txt\n");
    printf("sm2 decrypt:./sm2_utility --run_mode decypt_file_with_key --ctext_file_path ./3.txt --string_hex_key 0011aaaB --plain_file_path ./1.txt --type_of_curve 1172\n");
    printf("sm2 decrypt:./sm2_utility --run_mode decypt_file_with_key_file --ctext_file_path ./3.txt --key_file_path ./2.txt --plain_file_path ./1.txt\n");
    printf("sm2 decrypt:./sm2_utility --run_mode decypt_file_with_key_file --ctext_file_path ./3.txt --key_file_path ./2.txt --plain_file_path ./1.txt --type_of_curve 1172\n");
    printf("sm2 verify:./sm2_utility --run_mode verify_message --message_file_path ./1.txt --key_file_path ./2.txt --user_file_path ./3.txt --sig_file_path ./4.txt\n");
}
int main(int argc, char **argv) {
    int c = 0;
    char run_mode[64] = { 0 };
    char plain_file_path[128] = { 0 };
    char ctext_file_path[128] = { 0 };
    char key_file_path[128] = { 0 };
    char string_hex_key[64] = { 0 };
    char type_of_curve[64] = { 0 };
    char message_file_path[128] = { 0 };
    char user_file_path[128] = { 0 };
    char sig_file_path[128] = { 0 };
    if (argc < 3) {     // 至少有run_mode参数
        usage();
        return -1;
    }
    while ((c = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {  
        switch (c) {
        case 'r':
            l_opt_arg = optarg;
            snprintf(run_mode, sizeof(run_mode), "%s", l_opt_arg);
            break;  
        case 'p':
            l_opt_arg = optarg;
            snprintf(plain_file_path, sizeof(plain_file_path), "%s", l_opt_arg);
            break;
        case 'c':
            l_opt_arg = optarg;  
            snprintf(ctext_file_path, sizeof(ctext_file_path), "%s", l_opt_arg);
            break;
        case 'k':
            l_opt_arg = optarg;  
            snprintf(key_file_path, sizeof(key_file_path), "%s", l_opt_arg);
            break;
        case 's':
            l_opt_arg = optarg;  
            snprintf(string_hex_key, sizeof(string_hex_key), "%s", l_opt_arg);
            break;
        case 't':
            l_opt_arg = optarg;  
            snprintf(type_of_curve, sizeof(type_of_curve), "%s", l_opt_arg);
            break;
        case 'm':
            l_opt_arg = optarg;  
            snprintf(message_file_path, sizeof(message_file_path), "%s", l_opt_arg);
            break;
        case 'u':
            l_opt_arg = optarg;  
            snprintf(user_file_path, sizeof(user_file_path), "%s", l_opt_arg);
            break;
        case 'g':
            l_opt_arg = optarg;  
            snprintf(sig_file_path, sizeof(sig_file_path), "%s", l_opt_arg);
            break;
        case 'h':
            usage();
            break;
        default:
            usage();
            return -1;
            break;
        }
    }
    if (0 == strcmp(run_mode, "encypt_file")) {
        printf("encrypt file result:%d\n", sm2_encrypt_file(plain_file_path, ctext_file_path));
    }
    else if (0 == strcmp(run_mode, "decypt_file")) {
        printf("decrypt file result:%d\n", sm2_decrypt_file(ctext_file_path, plain_file_path));
    }
    else if (0 == strcmp(run_mode, "encypt_file_with_key")) {
        if (0 == type_of_curve[0]) {
            printf("encypt_file_with_key result:%d\n", sm2_encrypt_file_with_privkey(plain_file_path, string_hex_key, NID_sm2, ctext_file_path));
        }
        else {
            printf("encypt_file_with_key result:%d\n", sm2_encrypt_file_with_privkey(plain_file_path, string_hex_key, atoi(type_of_curve), ctext_file_path));
        }
    }
    else if (0 == strcmp(run_mode, "decypt_file_with_key")) {
        if (0 == type_of_curve[0]) {
            printf("decypt_file_with_key result:%d\n", sm2_decrypt_file_with_privkey(ctext_file_path, string_hex_key, NID_sm2, plain_file_path));
        }
        else {
            printf("decypt_file_with_key result:%d\n", sm2_decrypt_file_with_privkey(ctext_file_path, string_hex_key, atoi(type_of_curve), plain_file_path));
        }
    }
    else if (0 == strcmp(run_mode, "encypt_file_with_key_file")) {
        if (0 == type_of_curve[0]) {
            printf("encypt_file_with_key_file result:%d\n", sm2_encrypt_file_with_privkey_from_file(plain_file_path, key_file_path, NID_sm2, ctext_file_path));
        }
        else {
            printf("encypt_file_with_key_file result:%d\n", sm2_encrypt_file_with_privkey_from_file(plain_file_path, key_file_path, atoi(type_of_curve), ctext_file_path));
        }
    }
    else if (0 == strcmp(run_mode, "decypt_file_with_key_file")) {
        if (0 == type_of_curve[0]) {
            printf("decypt_file_with_key_file result:%d\n", sm2_decrypt_file_with_privkey_from_file(ctext_file_path, key_file_path, NID_sm2, plain_file_path));
        }
        else {
            printf("decypt_file_with_key_file result:%d\n", sm2_decrypt_file_with_privkey_from_file(ctext_file_path, key_file_path, atoi(type_of_curve), plain_file_path));
        }
    }
    else if (0 == strcmp(run_mode, "sign_message")) {
        printf("sign_message result:%d\n", sm2_sign_file(user_file_path, message_file_path, key_file_path, sig_file_path));
    }
    else if (0 == strcmp(run_mode, "verify_message")) {
        printf("verify_message result:%d\n", sm2_verify_file(user_file_path, message_file_path, key_file_path, sig_file_path));
    }

    return 0;
}