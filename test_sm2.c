#include "sm2_utility.h"
void test_sm2_encrypt() {
    const char *message = "hello sm2";
    const char *privkey_hex = "121b2110ab";
    uint8_t *ctext = NULL;
    int len = sm2_encrypt_message(message, privkey_hex, &ctext);
    int i = 0;
    for (;i < len;i++) {
        printf("%02x", ctext[i]);
    }
    printf("\n");
    uint8_t *plain = NULL;
    len = sm2_decrypt_message(ctext, len, privkey_hex, &plain);
    char buf[64] = "";
    memcpy(buf, (char *)plain, len);
    puts(buf);
    if (ctext) {
        OPENSSL_free(ctext);
    }
    if (plain) {
        OPENSSL_free(plain);
    }
}
void test_sm2_encrypt_file() {
    printf("%d\n", sm2_encrypt_file("./1.txt", "./3.txt"));
    printf("%d\n", sm2_decrypt_file("./3.txt", "./4.txt"));
}
int main() {    
    test_sm2_encrypt();
    test_sm2_encrypt_file();

    return 0;
}