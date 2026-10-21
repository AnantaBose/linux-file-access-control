#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <pwd.h>
#include "access_control.h"
#include "logger.h"

void show_identity(void) {
    uid_t uid = getuid();
    struct passwd *pw = getpwuid(uid);
    if (pw == NULL) {
        printf("Unknown user (UID %d)\n", (int)uid);
        return;
    }
    printf("Running as: %s (UID %d)\n", pw->pw_name, (int)uid);
}
int check_access(const char *path, int mode) {
    const char *action = (mode == R_OK) ? "ACCESS_READ"
                       : (mode == W_OK) ? "ACCESS_WRITE"
                       : (mode == X_OK) ? "ACCESS_EXEC" : "ACCESS";

    if (access(path, mode) == -1) {
        log_activity(action, path, strerror(errno));   /* denials get recorded too */
        return -1;
    }
    log_activity(action, path, "granted");
    return 0;
}
