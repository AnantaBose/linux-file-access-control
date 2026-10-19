#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <pwd.h>
#include <dirent.h>

#define LOG_PATH "/tmp/fmlog/activity.log"
#define LOG_MAX_BYTES (1024 * 1024)  

static int rotate_log(long max_bytes) {
    struct stat st;
    if (stat(LOG_PATH, &st) == -1) return -1;
    if (st.st_size < max_bytes) return 0;

    char old_path[256];
    snprintf(old_path, sizeof(old_path), "%s.1", LOG_PATH);
    if (rename(LOG_PATH, old_path) == -1) return -1;
    return 1;
}

void log_activity(const char *action, const char *target, const char *result) {
    rotate_log(LOG_MAX_BYTES);
FILE *f = fopen(LOG_PATH, "a");
    if (f == NULL) {
        perror("log");
        return;
    }

    time_t now = time(NULL);
    char timestr[64];
    strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", localtime(&now));

    struct passwd *pw = getpwuid(getuid());
    const char *user = pw ? pw->pw_name : "unknown";

    fprintf(f, "[%s] user=%s action=%s target=%s result=%s\n",
            timestr, user, action, target, result);
    fclose(f);
}
static void report_failure(const char *syscall_name, const char *action, const char *target) {
    int saved = errno;          
    perror(syscall_name);
    log_activity(action, target, strerror(saved));
}

void show_identity(void) {
    uid_t uid = getuid();
    struct passwd *pw = getpwuid(uid);
    if (pw == NULL) {
        printf("Unknown user (UID %d)\n", (int)uid);
        return;
    }
    printf("Running as: %s (UID %d)\n", pw->pw_name, (int)uid);
}

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
int check_access(const char *path, int mode) {
    const char *action = (mode == R_OK) ? "ACCESS_READ"
                       : (mode == W_OK) ? "ACCESS_WRITE"
                       : (mode == X_OK) ? "ACCESS_EXEC" : "ACCESS";

    if (access(path, mode) == -1) {
        log_activity(action, path, strerror(errno));  
        return -1;
    }
    log_activity(action, path, "granted");
    return 0;
}
void view_log(void) {
    FILE *f = fopen(LOG_PATH, "r");
    if (f == NULL) {
        printf("No log yet.\n");
        return;
    }
    char line[512];
    while (fgets(line, sizeof(line), f) != NULL) {
        printf("%s", line);
    }
    fclose(f);
}
static void read_line(const char *prompt, char *buf, size_t size) {
    printf("%s", prompt);
    if (fgets(buf, size, stdin) == NULL) {
        buf[0] = '\0';
        return;
    }
    buf[strcspn(buf, "\n")] = '\0';
}

int main(void) {
    char choice[16], path[512], text[64];

    show_identity();

    while (1) {
        printf("\n===== Linux File Manager =====\n");
        printf("1. Create file\n");
        printf("2. Delete file\n");
        printf("3. List directory\n");
        printf("4. Show file info and permissions\n");
        printf("5. Change permissions (chmod)\n");
        printf("6. Check my access (read/write/exec)\n");
        printf("7. View activity log\n");
        printf("8. Rotate log now\n");
        printf("0. Exit\n");
        read_line("Choice: ", choice, sizeof(choice));

        switch (atoi(choice)) {
            case 1:
                read_line("File path: ", path, sizeof(path));
                if (create_file(path) == 0) printf("Created.\n");
                break;
            case 2:
                read_line("File path: ", path, sizeof(path));
                if (delete_file(path) == 0) printf("Deleted.\n");
                break;
            case 3:
                read_line("Directory (e.g. .): ", path, sizeof(path));
                list_directory(path);
                break;
            case 4:
                read_line("File path: ", path, sizeof(path));
                if (show_file_info(path) == 0) show_permissions(path);
                break;
            case 5:
                read_line("File path: ", path, sizeof(path));
                read_line("New mode in octal (e.g. 644): ", text, sizeof(text));
                if (change_permissions(path, (mode_t)strtol(text, NULL, 8)) == 0)
                    printf("Permissions changed.\n");
                break;
            case 6:
                read_line("File path: ", path, sizeof(path));
                printf("Read:  %s\n", check_access(path, R_OK) == 0 ? "yes" : "no");
                printf("Write: %s\n", check_access(path, W_OK) == 0 ? "yes" : "no");
                printf("Exec:  %s\n", check_access(path, X_OK) == 0 ? "yes" : "no");
                break;
            case 7:
                view_log();
                break;
            case 8: {
                int r = rotate_log(0);
                if (r == 1) {
                    printf("Log rotated to %s.1\n", LOG_PATH);
                    log_activity("ROTATE", LOG_PATH, "success");
                } else {
                    printf("Rotation failed (no log yet, or not your file).\n");
                }
                break;
            }
            case 0:
                return 0;
            default:
                printf("Invalid choice.\n");
        }
    }
}
