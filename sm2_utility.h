#ifndef SM2_UTILITY_H
#define SM2_UTILITY_H
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include "crypto/sm2.h"
// 使用sm2加密字符串
// message指向明文字符串
// privkey_hex:16进制的私钥
// ctext:密文指针
// 函数返回密文长度 返回-1 则加密失败
int sm2_encrypt_message(const char *message, const char *privkey_hex, uint8_t **ctext);
// 使用sm2解密字符串
// ctext:密文指针
// ctext_len:密文长度
// privkey_hex:16进制的私钥
// message指向明文字符串
// 函数返回明文长度 返回-1 则解密失败
int sm2_decrypt_message(uint8_t *ctext, size_t ctext_len, const char *privkey_hex, uint8_t **message);
// 读文件内容到content
// 读成功返回文件字节数
// 读失败返回-1
int read_file_content(const char *file_path, char **content);
// 写文件内容
// 写成功返回文件字节数
// 写失败返回-1
int write_file_content(const char *file_path, void *content, size_t len);
// 使用sm2加密文件
// plain_file_path:明文文件绝对路径
// ctext_file_path:密文文件绝对路径
// 加密文件成功返回加密的字节数 否则返回-1
int sm2_encrypt_file(const char *plain_file_path, const char *ctext_file_path);
// 使用sm2解密文件
// ctext_file_path:密文文件绝对路径
// plain_file_path:明文文件绝对路径
// 解密文件成功返回解密的字节数 否则返回-1
int sm2_decrypt_file(const char *ctext_file_path, const char *plain_file_path);
#endif