#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/inotify.h>
#include "monitor.h"
#include "logger.h"

static volatile sig_atomic_t stop_monitor = 0;

static void on_sigint(int sig) {
    (void)sig;
    stop_monitor = 1;
}
void monitor_directory(const char *path) {
    int fd = inotify_init();
    if (fd == -1) {
        report_failure("inotify_init", "MONITOR", path);
        return;
    }

int wd = inotify_add_watch(fd, path,
        IN_CREATE | IN_DELETE | IN_MODIFY | IN_ATTRIB | IN_MOVED_FROM | IN_MOVED_TO);
    if (wd == -1) {
        report_failure("inotify_add_watch", "MONITOR", path);
        close(fd);
        return;
    }

struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sigint;
    sigaction(SIGINT, &sa, NULL);
    stop_monitor = 0;

    printf("Watching %s ... press Ctrl+C to stop.\n", path);
    log_activity("MONITOR_START", path, "success");
char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));

    while (!stop_monitor) {
        ssize_t len = read(fd, buf, sizeof(buf));   /* sleeps here: zero CPU while idle */
        if (len == -1) {
            if (errno != EINTR) perror("read");
            break;
        }
 for (char *p = buf; p < buf + len; ) {
            struct inotify_event *ev = (struct inotify_event *)p;

            const char *what = "EVENT_OTHER";
            if (ev->mask & IN_CREATE)          what = "EVENT_CREATE";
            else if (ev->mask & IN_DELETE)     what = "EVENT_DELETE";
            else if (ev->mask & IN_MODIFY)     what = "EVENT_MODIFY";
            else if (ev->mask & IN_ATTRIB)     what = "EVENT_ATTRIB";
            else if (ev->mask & IN_MOVED_FROM) what = "EVENT_MOVED_FROM";
            else if (ev->mask & IN_MOVED_TO)   what = "EVENT_MOVED_TO";

char full[1024];
            snprintf(full, sizeof(full), "%s/%s", path, ev->len ? ev->name : "");
            printf("%-18s %s\n", what, full);
            log_as("unknown", what, full, "observed");
p += sizeof(struct inotify_event) + ev->len;
        }
    }

    sa.sa_handler = SIG_DFL;
    sigaction(SIGINT, &sa, NULL);
    close(fd);
    printf("\nMonitor stopped.\n");
    log_activity("MONITOR_STOP", path, "success");
}
