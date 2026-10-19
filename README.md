# Linux File Management & Access Control System with Activity Logging

A C program built on POSIX syscalls that manages files, uses the real Linux
permission system for access control, and records every action (including
denials) to a shared activity log.

## How it works

Linux already enforces file permissions in the kernel. This project does not
replace that. It adds what Linux does not provide by default: a readable record
of who did what, and when, including denied attempts. Users are real Linux
accounts, and identity comes from `getuid()` / `getpwuid()`, so there is no
custom login.

## Features

- Create, delete, list files (`open`, `unlink`, `opendir`/`readdir`)
- File metadata and permission display (`stat`, bitwise decoding of `st_mode`)
- Change permissions (`chmod`)
- Permission checks before acting (`access`)
- Activity log with timestamp, user, action, target, result
- Failures are logged with the kernel's error reason (`errno`)
- Automatic log rotation at 1 MB (`stat` + `rename`) so the log cannot fill the disk

## Build and run

```bash
gcc -Wall -Wextra filemgr.c -o filemgr
mkdir -p /tmp/fmlog && chmod 777 /tmp/fmlog
./filemgr
```

## Demo: access denial between two users

```bash
echo "top secret" > /tmp/secret.txt
chmod 600 /tmp/secret.txt
cp filemgr /tmp/filemgr
chmod 666 /tmp/fmlog/activity.log      # after the first run creates it
sudo -u bob /tmp/filemgr                # option 6, path /tmp/secret.txt
./filemgr                               # option 7 shows bob's denials
```

Example log output:

```
[2026-10-19 05:13:16] user=bob action=ACCESS_READ target=/tmp/secret.txt result=Permission denied
```

## Progress

- [x] Stage 1: File management syscalls
- [x] Stage 2: Identity and access checks
- [x] Stage 3: Activity logging and menu interface
- [x] Log rotation
- [ ] Future work: inotify real-time monitor, per-user disk quota, anomaly alerts

## Known limitations

- The log is world-writable so every user can record events, which means it
  could also be edited. A stronger design would use a dedicated group with
  append-only rights (`chattr +a`).
- The log lives in `/tmp/fmlog` because Ubuntu's `fs.protected_regular`
  setting blocks other users from appending to files they do not own inside
  `/tmp` itself.
