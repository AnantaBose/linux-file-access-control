#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <pwd.h>
#include <dirent.h>
#include "fileops.h"
#include "logger.h"

int create_file(const char *path) {
    int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0644);
    if (fd == -1) {
        report_failure("open", "CREATE", path);
        return -1;
    }
    close(fd);
    log_activity("CREATE", path, "success");
    return 0;
}
int delete_file(const char *path) {
    if (unlink(path) == -1) {
        report_failure("unlink", "DELETE", path);
        return -1;
    }
    log_activity("DELETE", path, "success");
    return 0;
}
int show_file_info(const char *path) {
    struct stat file_info;
    if (stat(path, &file_info) == -1) {
        report_failure("stat", "STAT", path);
        return -1;
    }
    struct passwd *pw = getpwuid(file_info.st_uid);
    printf("Size: %ld bytes\n", (long)file_info.st_size);
    printf("Owner: %s (UID %d)\n", pw ? pw->pw_name : "unknown", (int)file_info.st_uid);
    log_activity("STAT", path, "success");
    return 0;
}

void show_permissions(const char *path) {
    struct stat file_info;
    if (stat(path, &file_info) == -1) {
        perror("stat");
        return;
    }
    if (file_info.st_mode & S_IRUSR) printf("Owner can read\n");
    if (file_info.st_mode & S_IWUSR) printf("Owner can write\n");
    if (file_info.st_mode & S_IXUSR) printf("Owner can execute\n");
    if (file_info.st_mode & S_IRGRP) printf("Group can read\n");
    if (file_info.st_mode & S_IWGRP) printf("Group can write\n");
    if (file_info.st_mode & S_IXGRP) printf("Group can execute\n");
    if (file_info.st_mode & S_IROTH) printf("Other can read\n");
    if (file_info.st_mode & S_IWOTH) printf("Other can write\n");
    if (file_info.st_mode & S_IXOTH) printf("Other can execute\n");
}
int change_permissions(const char *path, mode_t mode) {
    if (chmod(path, mode) == -1) {
        report_failure("chmod", "CHMOD", path);
        return -1;
    }
    log_activity("CHMOD", path, "success");
    return 0;
}
static void perm_string(mode_t m, char out[11]) {
    const char *chars = "rwxrwxrwx";
    out[0] = S_ISDIR(m) ? 'd' : '-';
    for (int i = 0; i < 9; i++) {
        out[i + 1] = (m & (1 << (8 - i))) ? chars[i] : '-';
    }
    out[10] = '\0';
}

void list_directory(const char *path) {
    DIR *dir = opendir(path);
    if (dir == NULL) {
        report_failure("opendir", "LIST", path);
        return;
    }
 struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        char full[1024];
        snprintf(full, sizeof(full), "%s/%s", path, entry->d_name);

        struct stat st;
        if (stat(full, &st) == -1) continue;

        char perms[11];
        perm_string(st.st_mode, perms);
        struct passwd *pw = getpwuid(st.st_uid);
        printf("%s %-8s %8ld  %s\n", perms, pw ? pw->pw_name : "?",
               (long)st.st_size, entry->d_name);
    }
    closedir(dir);
    log_activity("LIST", path, "success");
}
