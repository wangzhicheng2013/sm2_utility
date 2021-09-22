#include "sm2_utility.h"
int sm2_encrypt_message(const char *message, const char *privkey_hex, uint8_t **ctext) {
    int succ = 0;
    if (!message || !privkey_hex) {
        return -1;
    }
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime192v1);     // 椭圆曲线的基点
    if (!group) {
        return -1;
    }
    BIGNUM *priv = NULL;
    BN_hex2bn(&priv, privkey_hex);
    if (!priv) {
        succ = -1;
        goto DONE;
    }
    EC_KEY *key = EC_KEY_new();
    if (!key) {
        succ = -1;
        goto DONE;
    }
    EC_KEY_set_group(key, group);
    EC_POINT *pt = EC_POINT_new(group);
    if (!pt) {
        succ = -1;
        goto DONE;
    }
    EC_POINT_mul(group, pt, priv, NULL, NULL, NULL);    // 私钥乘基点得到公钥 公钥用来加密
    EC_KEY_set_public_key(key, pt);
    const EVP_MD *digest = EVP_sm3();
    if (!digest) {
        succ = -1;
        goto DONE;
    }
    size_t msg_len = strlen(message);
    size_t ctext_len = 0;
    sm2_ciphertext_size(key, digest, msg_len, &ctext_len);
    *ctext = (uint8_t *)OPENSSL_zalloc(ctext_len);
    if (!(*ctext)) {
        succ = -1;
        goto DONE;
    }
    if (1 != sm2_encrypt(key, digest, (const uint8_t *)message, msg_len, *ctext, &ctext_len)) {
        succ = -1;
        goto DONE;
    }
    succ = ctext_len;
DONE:
    EC_GROUP_free(group);
    BN_free(priv);
    EC_KEY_free(key);
    EC_POINT_free(pt);
    return succ;
}
int sm2_decrypt_message(uint8_t *ctext, size_t ctext_len, const char *privkey_hex, uint8_t **message) {
    int succ = 0;
    if (!message || !privkey_hex) {
        return -1;
    }
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime192v1);
    if (!group) {
        return -1;
    }
    BIGNUM *priv = NULL;
    BN_hex2bn(&priv, privkey_hex);
    if (!priv) {
        succ = -1;
        goto DONE;
    }
    EC_KEY *key = EC_KEY_new();
    if (!key) {
        succ = -1;
        goto DONE;
    }
    EC_KEY_set_group(key, group);
    EC_KEY_set_private_key(key, priv);
    const EVP_MD *digest = EVP_sm3();
    if (!digest) {
        succ = -1;
        goto DONE;
    }
    size_t msg_len = 0;
    sm2_plaintext_size(key, digest, ctext_len, &msg_len);
    *message = (uint8_t *)OPENSSL_zalloc(msg_len);
    if (!(*message)) {
        succ = -1;
        goto DONE;
    }
    if (1 != sm2_decrypt(key, digest, ctext, ctext_len, *message, &msg_len)) {
        succ = -1;
        goto DONE;
    }
    succ = msg_len;
DONE:
    EC_GROUP_free(group);
    BN_free(priv);
    EC_KEY_free(key);
    return succ;
}
int read_file_content(const char *file_path, char **content) {
    FILE *pFile = fopen(file_path, "rb");
    if (!pFile) {
        return -1;
    }
    fseek(pFile, 0, SEEK_END);
    size_t len = ftell(pFile);
    *content = (char *)malloc(len + 1);
    if (!content) {
        fclose(pFile);
        return -1;
    }
	rewind(pFile);
    if (len != fread(*content, 1, len, pFile)) {
        fclose(pFile);
        return -1;
    }
	(*content)[len] = '\0';
	fclose(pFile);
    return len;
}
int write_file_content(const char *file_path, void *content, size_t len) {
    FILE *pFile = fopen(file_path, "wb+");
    if (!pFile) {
        return -1;
    }
    int size = fwrite(content, 1, len, pFile);
    if (size != len) {
        size = -1;
    }
    fclose(pFile);
    return size;
}
int sm2_encrypt_file(const char *plain_file_path, const char *ctext_file_path) {
    int succ = 0;
    char *message = NULL;
    const char *privkey_hex = "900a2110ab";
    uint8_t *ctext = NULL;
    // 读明文
    int msg_len = read_file_content(plain_file_path, &message);
    if (msg_len <= 0) {
        succ = -1;
        goto DONE;
    }
    int ctext_len = sm2_encrypt_message(message, privkey_hex, &ctext);
    if (ctext_len <= 0) {
        succ = -1;
        goto DONE;
    }
    if (write_file_content(ctext_file_path, ctext, ctext_len) <= 0) {
        succ = -1;
        goto DONE;
    }
    succ = ctext_len;
DONE:
    if (ctext) {
        OPENSSL_free(ctext);
    }
    if (message) {
        free(message);
    }
    return succ;
}
int sm2_decrypt_file(const char *ctext_file_path, const char *plain_file_path) {
    int succ = 0;
    char *ctext = NULL;
    const char *privkey_hex = "900a2110ab";
    uint8_t *message = NULL;
    // 读密文
    int ctext_len = read_file_content(ctext_file_path, &ctext);
    if (ctext_len <= 0) {
        succ = -1;
        goto DONE;
    }
    int msg_len = sm2_decrypt_message(ctext, ctext_len, privkey_hex, &message);
    if (msg_len <= 0) {
        succ = -1;
        goto DONE;
    }
    if (write_file_content(plain_file_path, message, msg_len) <= 0) {
        succ = -1;
        goto DONE;
    }
    succ = msg_len;
DONE:
    if (ctext) {
        free(ctext);
    }
    if (message) {
        OPENSSL_free(message);
    }
    return succ;    
}
