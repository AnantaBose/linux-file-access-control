#include <stdio.h>
#include <string.h>
#include "analysis.h"
#include "logger.h"
#define MAX_USERS 32
#define ALERT_DENIALS 3
struct user_stats {
    char name[64];
    int total;
    int denied;
};

void analyze_log(void) {
    FILE *f = fopen(LOG_PATH, "r");
    if (f == NULL) {
        printf("No log yet.\n");
        return;
    }
 struct user_stats stats[MAX_USERS];
    int n = 0;
    char line[1024];

    while (fgets(line, sizeof(line), f) != NULL) {
        char user[64], action[64], target[512], result[256];

        if (sscanf(line, "[%*[^]]] user=%63s action=%63s target=%511s result=%255[^\n]",
                   user, action, target, result) != 4)
            continue;

        int i;
        for (i = 0; i < n; i++)
            if (strcmp(stats[i].name, user) == 0) break;

if (i == n) {
            if (n == MAX_USERS) continue;
            strncpy(stats[n].name, user, sizeof(stats[n].name) - 1);
            stats[n].name[sizeof(stats[n].name) - 1] = '\0';
            stats[n].total = 0;
            stats[n].denied = 0;
            n++;
        }
stats[i].total++;
        if (strstr(result, "Permission denied") != NULL)
            stats[i].denied++;
    }
    fclose(f);

    printf("\n%-12s %8s %8s\n", "USER", "ACTIONS", "DENIED");
    for (int i = 0; i < n; i++)
        printf("%-12s %8d %8d\n", stats[i].name, stats[i].total, stats[i].denied);

    for (int i = 0; i < n; i++)
        if (stats[i].denied >= ALERT_DENIALS)
            printf("ALERT: %s has %d denied access attempts\n", stats[i].name, stats[i].denied);
}
