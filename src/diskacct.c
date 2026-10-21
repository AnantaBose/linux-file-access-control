#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <dirent.h>
#include <pwd.h>
#include "diskacct.h"
#include "logger.h"

#define MAX_UIDS 64
#define QUOTA_BYTES (10LL * 1024 * 1024)
struct usage {
    uid_t uid;
    long long bytes;
};

static void add_usage(const char *dir, struct usage *u, int *n, int depth) {
    if (depth > 20) return;
    DIR *d = opendir(dir);
    if (d == NULL) return;

    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;

        char full[1024];
        snprintf(full, sizeof(full), "%s/%s", dir, e->d_name);
struct stat st;
        if (lstat(full, &st) == -1) continue; 
int i;
        for (i = 0; i < *n; i++)
            if (u[i].uid == st.st_uid) break;
        if (i == *n) {
            if (*n == MAX_UIDS) continue;
            u[*n].uid = st.st_uid;
            u[*n].bytes = 0;
            (*n)++;
        }

        u[i].bytes += (long long)st.st_blocks * 512;   /* real disk blocks used */
        if (S_ISDIR(st.st_mode)) add_usage(full, u, n, depth + 1);
    }
    closedir(d);
}
void disk_report(const char *dir) {
    struct statvfs vfs;
    if (statvfs(dir, &vfs) == -1) {
        report_failure("statvfs", "DISK_REPORT", dir);
        return;
    }

    double total = (double)vfs.f_blocks * vfs.f_frsize / (1024.0 * 1024 * 1024);
    double avail = (double)vfs.f_bavail * vfs.f_frsize / (1024.0 * 1024 * 1024);
    printf("Filesystem: %.1f GB total, %.1f GB free\n\n", total, avail);

    struct usage u[MAX_UIDS];
    int n = 0;
    add_usage(dir, u, &n, 0);
 printf("%-12s %12s\n", "USER", "USED (KB)");
    for (int i = 0; i < n; i++) {
        struct passwd *pw = getpwuid(u[i].uid);
        const char *name = pw ? pw->pw_name : "unknown";
        printf("%-12s %12lld\n", name, u[i].bytes / 1024);

        if (u[i].bytes > QUOTA_BYTES) {
            printf("WARNING: %s exceeds the %lld MB quota\n", name, QUOTA_BYTES / (1024 * 1024));
            log_activity("QUOTA_EXCEEDED", dir, name);
        }
    }
    log_activity("DISK_REPORT", dir, "success");
}
