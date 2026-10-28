#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include "users.h"
#include "logger.h"
#define UID_MIN_REGULAR 1000
#define UID_MAX_REGULAR 60000
#define MAX_USERS 64

struct acct {
    char name[64];
    uid_t uid;
    gid_t gid;
};
static int is_interesting(uid_t uid) {
    return uid == 0 || (uid >= UID_MIN_REGULAR && uid < UID_MAX_REGULAR);
}
static int collect_users(struct acct *out, int max) {
    int n = 0;
    struct passwd *pw;
    setpwent();
    while ((pw = getpwent()) != NULL && n < max) {
        if (!is_interesting(pw->pw_uid)) continue;
        strncpy(out[n].name, pw->pw_name, sizeof(out[n].name) - 1);
        out[n].name[sizeof(out[n].name) - 1] = '\0';
        out[n].uid = pw->pw_uid;
        out[n].gid = pw->pw_gid;
        n++;
    }
    endpwent();
    return n;
}
static int groups_of(const char *name, gid_t primary, gid_t **list) {
    int n = 16;
    gid_t *g = malloc(n * sizeof(gid_t));
    if (g == NULL) return -1;
    if (getgrouplist(name, primary, g, &n) == -1) {   /* buffer too small: n now holds the needed size */
        gid_t *bigger = realloc(g, n * sizeof(gid_t));
        if (bigger == NULL) { free(g); return -1; }
        g = bigger;
        if (getgrouplist(name, primary, g, &n) == -1) { free(g); return -1; }
    }
    *list = g;
    return n;
}
static int in_group(const struct acct *a, gid_t target) {
    if (a->gid == target) return 1;                    /* primary group */
    gid_t *g = NULL;
    int n = groups_of(a->name, a->gid, &g);            /* supplementary groups */
    int found = 0;
    for (int i = 0; i < n && !found; i++)
        if (g[i] == target) found = 1;
    free(g);
    return found;
}
void list_users(void) {
    printf("%-6s %-12s %-6s %-22s %s\n", "UID", "NAME", "GID", "HOME", "SHELL");
    setpwent();
    struct passwd *pw;
    while ((pw = getpwent()) != NULL) {
        if (!is_interesting(pw->pw_uid)) continue;
        printf("%-6d %-12s %-6d %-22s %s\n", (int)pw->pw_uid, pw->pw_name,
               (int)pw->pw_gid, pw->pw_dir, pw->pw_shell);
    }
    endpwent();
    log_activity("LIST_USERS", "/etc/passwd", "success");
}
void list_groups(void) {
    printf("%-6s %-14s %s\n", "GID", "GROUP", "EXTRA MEMBERS");
    struct group *gr;
    setgrent();
    while ((gr = getgrent()) != NULL) {
        if (!(gr->gr_gid == 0 || (gr->gr_gid >= UID_MIN_REGULAR && gr->gr_gid < UID_MAX_REGULAR)
              || (gr->gr_mem && gr->gr_mem[0])))
            continue;
        printf("%-6d %-14s", (int)gr->gr_gid, gr->gr_name);
        for (char **m = gr->gr_mem; m && *m; m++) printf(" %s", *m);
        printf("\n");
    }
    endgrent();
    log_activity("LIST_GROUPS", "/etc/group", "success");
}
void show_user_groups(const char *username) {
    struct passwd *pw = getpwnam(username);
    if (pw == NULL) {
        printf("No such user: %s\n", username);
        log_activity("USER_GROUPS", username, "user not found");
        return;
    }
    gid_t *g = NULL;
    int n = groups_of(pw->pw_name, pw->pw_gid, &g);
    if (n < 0) {
        printf("Could not read groups.\n");
        return;
    }
printf("%s (UID %d) belongs to:\n", pw->pw_name, (int)pw->pw_uid);
    for (int i = 0; i < n; i++) {
        struct group *gr = getgrgid(g[i]);
        printf("  %-14s GID %d%s\n", gr ? gr->gr_name : "?", (int)g[i],
               g[i] == pw->pw_gid ? "   (primary)" : "");
    }
    free(g);
    log_activity("USER_GROUPS", username, "success");
}
void access_matrix(const char *path) {
    struct stat st;
    if (stat(path, &st) == -1) {
        report_failure("stat", "ACCESS_MATRIX", path);
        return;
    }
    struct passwd *owner = getpwuid(st.st_uid);
    struct group  *grp   = getgrgid(st.st_gid);
    printf("File: %s   owner=%s  group=%s  mode=%03o%s\n", path,
           owner ? owner->pw_name : "?", grp ? grp->gr_name : "?",
           (unsigned)(st.st_mode & 0777), S_ISDIR(st.st_mode) ? "  (directory)" : "");

    struct acct u[MAX_USERS];
    int n = collect_users(u, MAX_USERS);

    printf("\n%-12s %-8s %s\n", "USER", "VIA", "ACCESS");
    for (int i = 0; i < n; i++) {
        int r, w, x;
        const char *via;
 if (u[i].uid == 0) {                                  /* root bypasses read/write checks */
            via = "root";
            r = 1; w = 1;
            x = S_ISDIR(st.st_mode) || (st.st_mode & 0111);   /* but needs some x bit to execute a file */
        } else if (u[i].uid == st.st_uid) {                   /* owner: ONLY the owner bits count */
            via = "owner";
            r = st.st_mode & S_IRUSR; w = st.st_mode & S_IWUSR; x = st.st_mode & S_IXUSR;
        } else if (in_group(&u[i], st.st_gid)) {              /* group member: ONLY the group bits count */
            via = "group";
            r = st.st_mode & S_IRGRP; w = st.st_mode & S_IWGRP; x = st.st_mode & S_IXGRP;
        } else {                                              /* everyone else */
            via = "other";
            r = st.st_mode & S_IROTH; w = st.st_mode & S_IWOTH; x = st.st_mode & S_IXOTH;
        }
        printf("%-12s %-8s %c%c%c\n", u[i].name, via, r ? 'r' : '-', w ? 'w' : '-', x ? 'x' : '-');
    }
log_activity("ACCESS_MATRIX", path, "success");
}

static int valid_username(const char *s) {
    size_t len = strlen(s);
    if (len == 0 || len > 32) return 0;
    if (!(islower((unsigned char)s[0]) || s[0] == '_')) return 0;
    for (size_t i = 1; i < len; i++)
        if (!(islower((unsigned char)s[i]) || isdigit((unsigned char)s[i]) || s[i] == '_' || s[i] == '-'))
            return 0;
    return 1;
}
int create_user(const char *username) {
    if (!valid_username(username)) {
        printf("Invalid user name.\n");
        log_activity("CREATE_USER", username, "invalid name");
        return -1;
    }
    if (geteuid() != 0) {
        printf("Creating users needs root. Run the program with sudo.\n");
        log_activity("CREATE_USER", username, "denied: not root");
        return -1;
    }

 pid_t pid = fork();                          /* make a child copy of this process */
    if (pid == -1) {
        report_failure("fork", "CREATE_USER", username);
        return -1;
    }
    if (pid == 0) {                              /* child: replace itself with useradd */
        execlp("useradd", "useradd", "-m", "-s", "/bin/bash", username, (char *)NULL);
        perror("execlp");                        /* only reached if exec failed */
        _exit(127);
    }

 int status;                                  /* parent: wait for the child to finish */
    if (waitpid(pid, &status, 0) == -1) {
        report_failure("waitpid", "CREATE_USER", username);
        return -1;
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        printf("User %s created.\n", username);
        log_activity("CREATE_USER", username, "success");
        return 0;
    }
    printf("useradd failed (exit code %d).\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    log_activity("CREATE_USER", username, "useradd failed");
    return -1;
}
