#include "file_utility.h"
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