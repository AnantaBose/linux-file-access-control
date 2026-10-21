#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include "logger.h"
int rotate_log(long max_bytes) {
    struct stat st;
    if (stat(LOG_PATH, &st) == -1) return -1;
    if (st.st_size < max_bytes) return 0;

    char old_path[256];
    snprintf(old_path, sizeof(old_path), "%s.1", LOG_PATH);
    if (rename(LOG_PATH, old_path) == -1) return -1;
    return 1;
}
void log_as(const char *user, const char *action, const char *target, const char *result) {
 mkdir(LOG_DIR, 0777);
 chmod(LOG_DIR, 0777);
 rotate_log(LOG_MAX_BYTES);

    FILE *f = fopen(LOG_PATH, "a");
    if (f == NULL) {
        perror("log");
        return;
    }
    chmod(LOG_PATH, 0666);
time_t now = time(NULL);
    char timestr[64];
    strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", localtime(&now));

    fprintf(f, "[%s] user=%s action=%s target=%s result=%s\n",
            timestr, user, action, target, result);
    fclose(f);
}

void log_activity(const char *action, const char *target, const char *result) {
    struct passwd *pw = getpwuid(getuid());
    log_as(pw ? pw->pw_name : "unknown", action, target, result);
}
void report_failure(const char *syscall_name, const char *action, const char *target) {
    int saved = errno;         /* save errno before anything can overwrite it */
    perror(syscall_name);
    log_activity(action, target, strerror(saved));
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
