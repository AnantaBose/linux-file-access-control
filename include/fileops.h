#ifndef FILEOPS_H
#define FILEOPS_H

#include <sys/types.h>

int  create_file(const char *path);
int  delete_file(const char *path);
int  show_file_info(const char *path);
void show_permissions(const char *path);
int  change_permissions(const char *path, mode_t mode);
void list_directory(const char *path);

#endif
