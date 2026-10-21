#ifndef LOGGER_H
#define LOGGER_H
#define LOG_DIR  "/tmp/fmlog"
#define LOG_PATH LOG_DIR "/activity.log"
#define LOG_MAX_BYTES (1024 * 1024)

int  rotate_log(long max_bytes);
void log_as(const char *user, const char *action, const char *target, const char *result);
void log_activity(const char *action, const char *target, const char *result);
void report_failure(const char *syscall_name, const char *action, const char *target);
void view_log(void);

#endif
