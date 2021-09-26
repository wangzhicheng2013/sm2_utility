#ifndef SM2_UTILITY_H
#define SM2_UTILITY_H
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
enum SM2_UTILITY_ERROR_CODE {
    GROUP_MAKE_FAILED    = -1,
    PRIKEY_MAKE_FAILED   = -2,
    ECKEY_MAKE_FAILED    = -3,
    ECPOINT_MAKE_FAILED  = -4,
    EVPSM3_MAKE_FAILED   = -5,
    ZMALLOC_MAKE_FAILED  = -6,
    ENCRYPT_MAKE_FAILED  = -7,
    DECRYPT_MAKE_FAILED  = -8,
    POINT_IS_EMPTY       = -9,
    READ_FILE_FAILED     = -10,
    WRITE_FILE_FAILED    = -11,
    PRIVKEY_HEX_INVALID  = -12,
    ECDSA_SIG_NULL       = -13,
    ECDSA_SIG_FAILED     = -14,
    SIG_VERIFY_FAILED    = -15,
};
// 检查privkey_hex是否满足16进制字符串
// 函数返回1 则满足要求 否则返回-12
int privkey_hex_is_valid(const char *privkey_hex);
// 使用sm2加密字符串
// message指向明文字符串
// msg_len:明文字节数
// privkey_hex:16进制的私钥 用于计算随机数
// curve_type:曲线类型
// ctext:密文指针
// 函数返回密文长度 返回-1 则加密失败
int sm2_encrypt_message(const char *message, 
                        size_t msg_len,
                        const char *privkey_hex,
                        int curve_type,
                        uint8_t **ctext);
// 使用sm2解密字符串
// ctext:密文指针
// ctext_len:密文长度
// privkey_hex:16进制的私钥 用于计算随机数
// curve_type:曲线类型
// message指向明文字符串
// 函数返回明文长度 返回-1 则解密失败
int sm2_decrypt_message(uint8_t *ctext, 
                        size_t ctext_len,
                        const char *privkey_hex,
                        int curve_type,
                        uint8_t **message);
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
// 使用sm2加密文件
// plain_file_path:明文文件绝对路径
// privkey_hex:16进制的私钥 比如01111aAbbbae
// curve_type:曲线类型
// ctext_file_path:密文文件绝对路径
// 加密文件成功返回加密的字节数 否则返回-1
int sm2_encrypt_file_with_privkey(const char *plain_file_path, 
                                  const char *privkey_hex, 
                                  int curve_type, 
                                  const char *ctext_file_path);
// 使用sm2加密文件
// plain_file_path:明文文件绝对路径
// privkey_path:私钥文件路径
// curve_type:曲线类型
// ctext_file_path:密文文件绝对路径
// 加密文件成功返回加密的字节数 否则返回-1
int sm2_encrypt_file_with_privkey_from_file(const char *plain_file_path, 
                                            const char *privkey_path,
                                            int curve_type, 
                                            const char *ctext_file_path);
// 使用sm2解密文件
// ctext_file_path:密文文件绝对路径
// plain_file_path:明文文件绝对路径
// 解密文件成功返回解密的字节数 否则返回-1
int sm2_decrypt_file(const char *ctext_file_path, const char *plain_file_path);
// 使用sm2解密文件
// ctext_file_path:密文文件绝对路径
// privkey_hex:16进制的私钥 比如01111aAbbbae
// curve_type:曲线类型
// plain_file_path:明文文件绝对路径
// 解密文件成功返回解密的字节数 否则返回-1
int sm2_decrypt_file_with_privkey(const char *ctext_file_path, 
                                  const char *privkey_hex,
                                  int curve_type, 
                                  const char *plain_file_path);
// 使用sm2解密文件
// ctext_file_path:密文文件绝对路径
// privkey_path:私钥文件路径
// curve_type:曲线类型
// plain_file_path:明文文件绝对路径
// 解密文件成功返回解密的字节数 否则返回-1
int sm2_decrypt_file_with_privkey_from_file(const char *ctext_file_path,
                                            const char *privkey_path,
                                            int curve_type, 
                                            const char *plain_file_path);
// 创建EC组
// 以下参数为16进制点坐标
EC_GROUP *create_EC_group(const char *p_hex, const char *a_hex,
                          const char *b_hex, const char *x_hex,
                          const char *y_hex, const char *order_hex,
                          const char *cof_hex);
// 使用sm2对消息进行签名
// user_name:签名
// message:消息体
// privkey_hex:16进制的私钥
// sig_file_path:签名文件路径
// 签名成功返回1 失败返回错误码
int sm2_sign_message(const char *user_name,
             const char *message,
             size_t msg_len,
             const char *privkey_hex,
             const char *sig_file_path);
// 使用sm2对消息签名进行校验
// user_name:签名
// message:消息体
// privkey_hex:16进制的私钥
// sig_file_path:签名文件路径
// 校验成功返回1 失败返回错误码
int sm2_verify_message(const char *user_name,
             const char *message,
             size_t msg_len,
             const char *privkey_hex,
             const char *sig_file_path);
// 使用sm2对消息进行签名
// user_name_path:签名文件路径
// message_path:消息体文件路径
// privkey_hex_path:16进制的私钥路径
// sig_file_path:签名文件路径
// 签名成功返回1 失败返回错误码
int sm2_sign_file(const char *user_name_path,
             const char *message_path,
             const char *privkey_hex_path,
             const char *sig_file_path);
// 使用sm2对消息签名进行校验
// user_name_path:签名文件路径
// message_path:消息体文件路径
// privkey_hex_path:16进制的私钥路径
// sig_file_path:签名文件路径
// 签名成功返回1 失败返回错误码
int sm2_verify_file(const char *user_name_path,
             const char *message_path,
             const char *privkey_hex_path,
             const char *sig_file_path);

#endif