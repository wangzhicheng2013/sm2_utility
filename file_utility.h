#ifndef FILE_UTILITY_H
#define FILE_UTILITY_H
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
// 读文件内容到content
// 读成功返回文件字节数
// 读失败返回-1
int read_file_content(const char *file_path, char **content);
// 写文件内容
// 写成功返回文件字节数
// 写失败返回-1
int write_file_content(const char *file_path, void *content, size_t len);

#endif