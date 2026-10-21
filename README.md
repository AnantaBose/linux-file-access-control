# Linux File Management & Access Control System with Activity Logging

A modular C application built on POSIX syscalls. It manages files, relies on
the real Linux permission system for access control, and records every action,
including denied attempts, in a shared activity log. It then analyzes that log,
watches directories in real time, and reports per-user disk usage.

Linux already enforces file permissions in the kernel, and this project does not
replace that. It adds what Linux does not provide by default: a readable record
of who did what and when, automatic analysis of that record, and lightweight
real-time and resource visibility. Users are real Linux accounts. Identity comes
from `getuid()` / `getpwuid()`, so there is no custom login.
## Architecture

| Layer | Module | What it does | Key syscalls |
|---|---|---|---|
| File operations | `fileops.c` | create, delete, list, inspect, chmod | `open`, `unlink`, `stat`, `chmod`, `opendir`/`readdir` |
| Access control | `access_control.c` | identity and permission checks | `getuid`, `getpwuid`, `access` |
| Activity logging | `logger.c` | timestamped per-user log, errno-based failure reasons, rotation at 1 MB | `fopen`, `rename`, `stat` |
| Log analysis | `analysis.c` | per-user summary, alert on repeated denials | log parsing |
| Real-time monitor | `monitor.c` | reports file changes as they happen, with no CPU use while idle | `inotify_*`, `read`, `sigaction` |
| Resource accounting | `diskacct.c` | filesystem usage, per-user disk use, quota warning | `statvfs`, `lstat` |
## Project structure

```
include/   header files, one per module
src/       main.c (menu) plus one .c file per module
Makefile
```

## Build and run

```bash
make
./filemgr
```

`make clean` removes build output.
## Demo: access denial between two real users

```bash
echo "top secret" > /tmp/secret.txt
chmod 600 /tmp/secret.txt
cp filemgr /tmp/filemgr
sudo -u bob /tmp/filemgr        # option 6, path /tmp/secret.txt
./filemgr                       # option 7 (log) and option 9 (analysis)
```

Example log lines:
```
[2026-10-19 05:13:16] user=bob action=ACCESS_READ target=/tmp/secret.txt result=Permission denied
```

The same program and the same file give different answers depending on who runs
it. The kernel makes that decision, and this system records it.

## Progress

- [x] File operations
- [x] Identity and access checks
- [x] Activity logging and log rotation
- [x] Log analysis with denial alerts
- [x] Real-time directory monitor (inotify)
- [x] Disk usage accounting with quota warning
- [ ] Future work: append-only log protection, per-user quotas from a config file, load-aware background tasks

## Known limitations
- Only actions performed through this tool are attributed to a user. The
  monitor catches changes made by other programs, but inotify cannot say which
  user made them, so those events are logged as user `unknown`.
- The log is world-writable so every user can record events, which also means
  it could be edited. A stronger design would use a dedicated group with
  append-only rights (`chattr +a`).
- The log lives in `/tmp/fmlog` because Ubuntu's `fs.protected_regular`
  setting stops users from appending to files they do not own directly inside
  `/tmp`.
- The denial alert is a simple threshold, not a validated detection method.
- Log analysis reads only the current log file, not rotated copies.
- inotify works on Linux filesystems such as the WSL home folder, but is not
  reliable on Windows folders under `/mnt/c`.
