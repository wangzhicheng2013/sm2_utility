#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include "crypto/sm2.h"
int main(int argc, char **argv) {
    if (argc != 4) {
        return -1;
    }
    // argv[1] 明文
    // argv[2] 秘钥
    // argv[3] 密文
    FILE *fp = fopen(argv[1], "rb");
    fseek(fp, 0, SEEK_END);
    size_t len = ftell(fp);
    char *message = (char *)malloc(len + 1);
	rewind(fp);
    fread(message, 1, len, fp);
	message[len] = '\0';
	fclose(fp);
    // 加密
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sm2);
    BIGNUM *priv = NULL;
    BN_hex2bn(&priv, argv[2]);
    EC_KEY *key = EC_KEY_new();
    EC_KEY_set_group(key, group);
    EC_POINT *pt = EC_POINT_new(group);
    EC_POINT_mul(group, pt, priv, NULL, NULL, NULL);
    EC_KEY_set_public_key(key, pt);
    const EVP_MD *digest = EVP_sm3();
    size_t ctext_len = 0;
    sm2_ciphertext_size(key, digest, len, &ctext_len);
    uint8_t *ctext = (uint8_t *)OPENSSL_zalloc(ctext_len);
    sm2_encrypt(key, digest, (const uint8_t *)message, len, ctext, &ctext_len);
    EC_GROUP_free(group);
    BN_free(priv);
    EC_KEY_free(key);
    EC_POINT_free(pt);   
    free(message);
    // 写密文
    fp = fopen(argv[3], "wb+");
    fwrite(ctext, 1, ctext_len, fp);
    fclose(fp);
    OPENSSL_free(ctext);

    return 0;
}