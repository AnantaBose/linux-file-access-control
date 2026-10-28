#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "policy.h"
#include "logger.h"
#include "users.h"

#define DATA_DIR   "/tmp/fmdata"
#define POLICY_DB  LOG_DIR "/policy.conf"
#define FILES_DB   LOG_DIR "/files.db"
#define GRANTS_DB  LOG_DIR "/grants.db"
#define ALL_POWERS "rwdgcuA"
#define MAX_NAMES  64

static void ensure_setup(void) {
    mkdir(LOG_DIR, 0777);
    chmod(LOG_DIR, 0777);
    mkdir(DATA_DIR, 0777);
    chmod(DATA_DIR, 0777);

    if (access(POLICY_DB, F_OK) != 0) {
        FILE *f = fopen(POLICY_DB, "w");
        if (f != NULL) {
            fputs("# prefix  role     powers\n"
                  "# r=read w=write d=delete g=grant c=create u=manage users A=all files\n"
                  "a_  admin    rwdgcuA\n"
                  "m_  manager  rwdgc\n"
                  "u_  user     rwc\n"
                  "*   guest    -\n", f);
            fclose(f);
            chmod(POLICY_DB, 0666);
        }
    }
}

static void whoami(char *out, size_t n) {
    struct passwd *pw = getpwuid(getuid());
    snprintf(out, n, "%s", pw ? pw->pw_name : "unknown");
}

static void role_of(const char *user, char *role, size_t rn,
                    char *powers, size_t pn) {
    if (strcmp(user, "root") == 0) {
        snprintf(role, rn, "root");
        snprintf(powers, pn, "%s", ALL_POWERS);
        return;
    }

    snprintf(role, rn, "guest");
    powers[0] = '\0';
    ensure_setup();

    FILE *f = fopen(POLICY_DB, "r");
    if (f == NULL) return;

    char line[256];
    while (fgets(line, sizeof(line), f) != NULL) {
        char prefix[32], r[32], p[32];

        if (line[0] == '#') continue;
        if (sscanf(line, "%31s %31s %31s",
                   prefix, r, p) != 3) continue;

        if (strcmp(prefix, "*") == 0 ||
            strncmp(user, prefix, strlen(prefix)) == 0) {
            snprintf(role, rn, "%s", r);
            snprintf(powers, pn, "%s",
                     strcmp(p, "-") == 0 ? "" : p);
            break;
        }
    }

    fclose(f);
}

static int owner_of(const char *file, char *owner, size_t n) {
    FILE *f = fopen(FILES_DB, "r");
    if (f == NULL) return 0;

    char line[256], a[128], b[64];
    int found = 0;

    while (fgets(line, sizeof(line), f) != NULL) {
        if (sscanf(line, "%127s %63s", a, b) == 2 &&
            strcmp(a, file) == 0) {
            snprintf(owner, n, "%s", b);
            found = 1;
            break;
        }
    }

    fclose(f);
    return found;
}

static int grant_of(const char *file, const char *user,
                    char *powers, size_t pn,
                    char *grantor, size_t gn) {
    FILE *f = fopen(GRANTS_DB, "r");
    if (f == NULL) return 0;

    char line[256], a[128], b[64], c[16], d[64];
    int found = 0;

    while (fgets(line, sizeof(line), f) != NULL) {
        if (sscanf(line, "%127s %63s %15s %63s",
                   a, b, c, d) == 4 &&
            strcmp(a, file) == 0 &&
            strcmp(b, user) == 0) {
            snprintf(powers, pn, "%s", c);
            snprintf(grantor, gn, "%s", d);
            found = 1;
            break;
        }
    }

    fclose(f);
    return found;
}

static void db_remove(const char *db, const char *file,
                      const char *user) {
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s.tmp", db);

    FILE *in = fopen(db, "r");
    if (in == NULL) return;

    FILE *out = fopen(tmp, "w");
    if (out == NULL) {
        fclose(in);
        return;
    }

    char line[256], a[128], b[64];

    while (fgets(line, sizeof(line), in) != NULL) {
        int n = sscanf(line, "%127s %63s", a, b);
        int match = (n >= 1 && strcmp(a, file) == 0 &&
                    (user == NULL ||
                    (n == 2 && strcmp(b, user) == 0)));

        if (!match) fputs(line, out);
    }

    fclose(in);
    fclose(out);
    chmod(tmp, 0666);
    rename(tmp, db);
}

static void db_append(const char *db, const char *text) {
    FILE *f = fopen(db, "a");
    if (f == NULL) return;

    fputs(text, f);
    fclose(f);
    chmod(db, 0666);
}

static int allowed(const char *user, const char *file,
                   char power, char *why, size_t wn) {
    char role[32], pows[32], owner[64];

    role_of(user, role, sizeof(role), pows, sizeof(pows));

    if (!owner_of(file, owner, sizeof(owner))) {
        snprintf(why, wn, "no such managed file");
        return 0;
    }

    if (strcmp(owner, user) == 0) {
        if (strchr(pows, power) != NULL) {
            snprintf(why, wn, "owner");
            return 1;
        }

        snprintf(why, wn, "role %s lacks '%c'", role, power);
        return 0;
    }

    if (strchr(pows, 'A') != NULL &&
        strchr(pows, power) != NULL) {
        snprintf(why, wn, "%s override", role);
        return 1;
    }

    char gp[16], gb[64];

    if (grant_of(file, user, gp, sizeof(gp),
                 gb, sizeof(gb))) {
        if (strchr(gp, power) != NULL) {
            snprintf(why, wn, "granted by %s", gb);
            return 1;
        }

        snprintf(why, wn, "grant '%s' does not include '%c'",
                 gp, power);
        return 0;
    }

    snprintf(why, wn, "not owner, no grant");
    return 0;
}

static int authorize(const char *file, char power,
                     const char *action) {
    char user[64], why[128], res[400];
    whoami(user, sizeof(user));

    if (allowed(user, file, power, why, sizeof(why))) {
        snprintf(res, sizeof(res), "granted (%s)", why);
        log_activity(action, file, res);
        return 1;
    }

    printf("DENIED: %s\n", why);
    snprintf(res, sizeof(res),
             "Permission denied (policy: %s)", why);
    log_activity(action, file, res);
    return 0;
}

static int valid_name(const char *s) {
    size_t len = strlen(s);

    if (len == 0 || len > 64 || s[0] == '.')
        return 0;

    for (size_t i = 0; i < len; i++) {
        if (!(isalnum((unsigned char)s[i]) ||
              s[i] == '.' || s[i] == '_' ||
              s[i] == '-'))
            return 0;
    }

    return 1;
}

static void full_path(const char *name, char *out, size_t n) {
    snprintf(out, n, "%s/%s", DATA_DIR, name);
}

void policy_show_roles(void) {
    ensure_setup();

    printf("Powers: r=read  w=write  d=delete  "
           "g=grant others access  c=create files  "
           "u=manage users  A=acts on ALL files\n\n");

    printf("%-10s %-10s %s\n", "PREFIX", "ROLE", "POWERS");
    printf("%-10s %-10s %s\n", "(root)", "root", ALL_POWERS);

    FILE *f = fopen(POLICY_DB, "r");
    if (f == NULL) return;

    char line[256];

    while (fgets(line, sizeof(line), f) != NULL) {
        char prefix[32], r[32], p[32];

        if (line[0] == '#') continue;

        if (sscanf(line, "%31s %31s %31s",
                   prefix, r, p) == 3)
            printf("%-10s %-10s %s\n", prefix, r, p);
    }

    fclose(f);
    log_activity("SHOW_ROLES", POLICY_DB, "success");
}

static int collect_names(char names[][64], int max) {
    int n = 0;
    struct passwd *pw;

    setpwent();

    while ((pw = getpwent()) != NULL && n < max) {
        if (pw->pw_uid == 0 ||
            (pw->pw_uid >= 1000 && pw->pw_uid < 60000)) {
            snprintf(names[n], 64, "%s", pw->pw_name);
            n++;
        }
    }

    endpwent();
    return n;
}

void policy_list_users(void) {
    ensure_setup();

    char names[MAX_NAMES][64];
    int n = collect_names(names, MAX_NAMES);

    printf("%-14s %-10s %s\n", "USER", "ROLE", "POWERS");

    for (int i = 0; i < n; i++) {
        char role[32], pows[32];

        role_of(names[i], role, sizeof(role),
                pows, sizeof(pows));

        printf("%-14s %-10s %s\n",
               names[i], role, pows[0] ? pows : "-");
    }

    log_activity("LIST_POLICY_USERS", POLICY_DB, "success");
}

int policy_create_user(const char *username) {
    char me[64], role[32], pows[32], why[96];

    whoami(me, sizeof(me));
    role_of(me, role, sizeof(role), pows, sizeof(pows));

    if (strchr(pows, 'u') == NULL) {
        printf("DENIED: role %s lacks 'u' (manage users)\n", role);

        snprintf(why, sizeof(why),
                 "Permission denied (policy: role %s lacks 'u')",
                 role);

        log_activity("CREATE_USER", username, why);
        return -1;
    }

    if (create_user(username) == 0) {
        role_of(username, role, sizeof(role),
                pows, sizeof(pows));

        printf("  -> by its name prefix, %s is a '%s' "
               "with powers: %s\n",
               username, role, pows[0] ? pows : "-");
        return 0;
    }

    return -1;
}

int policy_new_file(const char *name) {
    char me[64], role[32], pows[32], res[160];

    if (!valid_name(name)) {
        printf("Invalid name (letters, digits, . _ - only; no slashes).\n");
        return -1;
    }

    ensure_setup();
    whoami(me, sizeof(me));
    role_of(me, role, sizeof(role), pows, sizeof(pows));

    if (strchr(pows, 'c') == NULL) {
        printf("DENIED: role %s lacks 'c' (create files)\n", role);

        snprintf(res, sizeof(res),
                 "Permission denied (policy: role %s lacks 'c')",
                 role);

        log_activity("NEW_FILE", name, res);
        return -1;
    }

    char path[256], existing[64];
    full_path(name, path, sizeof(path));

    if (owner_of(name, existing, sizeof(existing))) {
        printf("A managed file called %s already exists (owner %s).\n",
               name, existing);
        log_activity("NEW_FILE", name, "File exists");
        return -1;
    }

    int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0666);

    if (fd == -1) {
        report_failure("open", "NEW_FILE", name);
        return -1;
    }

    fchmod(fd, 0666);
    close(fd);

    snprintf(res, sizeof(res), "%s %s\n", name, me);
    db_append(FILES_DB, res);

    snprintf(res, sizeof(res), "granted (owner %s)", me);
    log_activity("NEW_FILE", name, res);

    printf("Created %s. Owner: %s (%s)\n", name, me, role);
    return 0;
}

int policy_read_file(const char *name) {
    if (!valid_name(name)) {
        printf("Invalid name.\n");
        return -1;
    }

    ensure_setup();

    if (!authorize(name, 'r', "READ"))
        return -1;

    char path[256], buf[1024];
    full_path(name, path, sizeof(path));

    int fd = open(path, O_RDONLY);

    if (fd == -1) {
        report_failure("open", "READ", name);
        return -1;
    }

    ssize_t n;
    int any = 0;

    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        if (write(STDOUT_FILENO, buf, (size_t)n) < 0)
            break;
        any = 1;
    }

    if (!any) printf("(empty)\n");

    close(fd);
    return 0;
}

int policy_write_file(const char *name, const char *text) {
    if (!valid_name(name)) {
        printf("Invalid name.\n");
        return -1;
    }

    ensure_setup();

    if (!authorize(name, 'w', "WRITE"))
        return -1;

    char path[256], line[1100];
    full_path(name, path, sizeof(path));

    int fd = open(path, O_WRONLY | O_APPEND);

    if (fd == -1) {
        report_failure("open", "WRITE", name);
        return -1;
    }

    snprintf(line, sizeof(line), "%s\n", text);

    if (write(fd, line, strlen(line)) == -1) {
        report_failure("write", "WRITE", name);
        close(fd);
        return -1;
    }

    close(fd);
    printf("Written.\n");
    return 0;
}

int policy_delete_file(const char *name) {
    if (!valid_name(name)) {
        printf("Invalid name.\n");
        return -1;
    }

    ensure_setup();

    if (!authorize(name, 'd', "DELETE_MANAGED"))
        return -1;

    char path[256];
    full_path(name, path, sizeof(path));

    if (unlink(path) == -1) {
        report_failure("unlink", "DELETE_MANAGED", name);
        return -1;
    }

    db_remove(FILES_DB, name, NULL);
    db_remove(GRANTS_DB, name, NULL);

    printf("Deleted.\n");
    return 0;
}

static int may_distribute(const char *file, char *me, size_t mn,
                          char *why, size_t wn) {
    char role[32], pows[32], owner[64];

    whoami(me, mn);
    role_of(me, role, sizeof(role), pows, sizeof(pows));

    if (!owner_of(file, owner, sizeof(owner))) {
        snprintf(why, wn, "no such managed file");
        return 0;
    }

    if (strchr(pows, 'g') == NULL) {
        snprintf(why, wn, "role %s lacks 'g'", role);
        return 0;
    }

    if (strcmp(owner, me) != 0 &&
        strchr(pows, 'A') == NULL) {
        snprintf(why, wn, "not the owner and not an admin");
        return 0;
    }

    snprintf(why, wn, "%s",
             strcmp(owner, me) == 0 ? "owner" : "admin");
    return 1;
}

int policy_grant(const char *name, const char *user,
                 const char *powers) {
    char me[64], why[128], res[400], owner[64];

    if (!valid_name(name)) {
        printf("Invalid name.\n");
        return -1;
    }

    ensure_setup();

    if (!may_distribute(name, me, sizeof(me),
                        why, sizeof(why))) {
        printf("DENIED: %s\n", why);

        snprintf(res, sizeof(res),
                 "Permission denied (policy: %s)", why);

        log_activity("GRANT", name, res);
        return -1;
    }

    if (powers[0] == '\0' ||
        strspn(powers, "rwd") != strlen(powers)) {
        printf("Powers can only be made of r, w, d (e.g. rw).\n");
        return -1;
    }

    if (getpwnam(user) == NULL) {
        printf("No such user: %s\n", user);
        return -1;
    }

    owner_of(name, owner, sizeof(owner));

    if (strcmp(owner, user) == 0) {
        printf("%s already owns this file.\n", user);
        return -1;
    }

    db_remove(GRANTS_DB, name, user);

    snprintf(res, sizeof(res), "%s %s %s %s\n",
             name, user, powers, me);

    db_append(GRANTS_DB, res);

    snprintf(res, sizeof(res),
             "granted %s to %s (by %s, as %s)",
             powers, user, me, why);

    log_activity("GRANT", name, res);

    printf("%s now has '%s' on %s (given by %s).\n",
           user, powers, name, me);

    return 0;
}

int policy_revoke(const char *name, const char *user) {
    char me[64], why[128], res[400];

    if (!valid_name(name)) {
        printf("Invalid name.\n");
        return -1;
    }

    ensure_setup();

    if (!may_distribute(name, me, sizeof(me),
                        why, sizeof(why))) {
        printf("DENIED: %s\n", why);

        snprintf(res, sizeof(res),
                 "Permission denied (policy: %s)", why);

        log_activity("REVOKE", name, res);
        return -1;
    }

    db_remove(GRANTS_DB, name, user);

    snprintf(res, sizeof(res),
             "revoked %s (by %s)", user, me);

    log_activity("REVOKE", name, res);

    printf("Revoked %s's extra access to %s.\n", user, name);
    return 0;
}

void policy_file_report(const char *name) {
    char owner[64], orole[32], opows[32];

    if (!valid_name(name)) {
        printf("Invalid name.\n");
        return;
    }

    ensure_setup();

    if (!owner_of(name, owner, sizeof(owner))) {
        printf("No managed file called %s.\n", name);
        return;
    }

    role_of(owner, orole, sizeof(orole),
            opows, sizeof(opows));

    printf("File: %s   owner: %s (%s)\n\n",
           name, owner, orole);

    char names[MAX_NAMES][64];
    int n = collect_names(names, MAX_NAMES);

    const char order[] = "rwd";

    printf("%-14s %-10s %-6s %s\n",
           "USER", "ROLE", "POWERS", "VIA");

    for (int i = 0; i < n; i++) {
        char role[32], pows[32], why[128];
        char firstwhy[128] = "none";
        char mark[5] = "----";

        role_of(names[i], role, sizeof(role),
                pows, sizeof(pows));

        for (int k = 0; k < 3; k++) {
            if (allowed(names[i], name, order[k],
                        why, sizeof(why))) {
                mark[k] = order[k];

                if (strcmp(firstwhy, "none") == 0)
                    snprintf(firstwhy, sizeof(firstwhy),
                             "%s", why);
            }
        }

        printf("%-14s %-10s %-6s %s\n",
               names[i], role, mark, firstwhy);
    }

    log_activity("FILE_REPORT", name, "success");
}
