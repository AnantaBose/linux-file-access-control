#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include "logger.h"
#include "fileops.h"
#include "access_control.h"
#include "analysis.h"
#include "monitor.h"
#include "diskacct.h"

static void read_line(const char *prompt, char *buf, size_t size) {
    printf("%s", prompt);
    if (fgets(buf, size, stdin) == NULL) {
        buf[0] = '\0';
        return;
}
    buf[strcspn(buf, "\n")] = '\0';    /* strip the newline */
}

static void print_menu(void) {
    printf("\n===== Linux File Manager =====\n");
    printf("1. Create file\n");
    printf("2. Delete file\n");
    printf("3. List directory\n");
    printf("4. Show file info and permissions\n");
    printf("5. Change permissions (chmod)\n");
    printf("6. Check my access (read/write/exec)\n");
    printf("7. View activity log\n");
    printf("8. Rotate log now\n");
    printf("9. Analyze log (summary + alerts)\n");
    printf("10. Monitor a directory (real-time)\n");
 printf("11. Disk usage report\n");
    printf("0. Exit\n");
}

int main(void) {
    char choice[16], path[512], text[64];

    show_identity();

    while (1) {
        print_menu();
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
            case 9:
                analyze_log();
                break;
case 10:
                read_line("Directory to watch (e.g. .): ", path, sizeof(path));
                monitor_directory(path);
                break;
            case 11:
                read_line("Directory to scan (e.g. .): ", path, sizeof(path));
                disk_report(path);
                break;
            case 0:
                return 0;
            default:
                printf("Invalid choice.\n");
        }
    }
}
