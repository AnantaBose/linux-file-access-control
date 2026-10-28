# Linux File Management & Access Control System with Activity Logging

A modular C application built on POSIX syscalls. It manages files, relies on the
Linux kernel for permission enforcement, adds a role-based access policy with
owners and grants, records every action (including denials) in a shared log,
and analyzes that log. It also watches directories in real time, reports disk
usage per user, and shows users and groups.

Linux enforces file permissions in the kernel but keeps no record of who tried
what. This project adds the record, the analysis, and a policy layer that
decides who may distribute access.

## Architecture

| Layer | Module | What it does | Key syscalls |
|---|---|---|---|
| File operations | `fileops.c` | create, delete, list, inspect, chmod | `open`, `unlink`, `stat`, `chmod`, `opendir` |
| Access control | `access_control.c` | identity and permission checks | `getuid`, `getpwuid`, `access` |
| Users and groups | `users.c` | list users and groups, kernel access table per file, create users | `getpwent`, `getgrent`, `getgrouplist`, `fork`, `execlp`, `waitpid` |
| Access policy | `policy.c` | roles by name prefix, owners, grants | `open`, `read`, `write`, `unlink` |
| Activity logging | `logger.c` | timestamped per-user log, rotation at 1 MB | `fopen`, `rename`, `stat` |
| Log analysis | `analysis.c` | per-user summary, alert on repeated denials | log parsing |
| Real-time monitor | `monitor.c` | file-change events, no CPU use while idle | `inotify`, `read`, `sigaction` |
| Disk accounting | `diskacct.c` | filesystem and per-user usage, quota warning | `statvfs`, `lstat` |

## Access policy: who holds which power

A user's role comes from the start of their Linux user name. Powers:
`r` read, `w` write, `d` delete, `g` grant access to others, `c` create files,
`u` manage users, `A` acts on all files.

| Name starts with | Role | Powers |
|---|---|---|
| (root) | root | rwdgcuA |
| `a_` | admin | rwdgcuA |
| `m_` | manager | rwdgc |
| `u_` | user | rwc |
| anything else | guest | none (only what is granted) |

- The **owner** of a managed file is whoever created it.
- Only the owner (if their role has `g`) or an admin may **grant** or **revoke**
  access, and only `r`, `w` or `d`. Each grant records who gave it.
- Every decision is checked in this order: owner, admin override, explicit
  grant, otherwise denied. The reason is printed and logged.
- The rules live in `/tmp/fmlog/policy.conf` and can be edited.


## Build and run

```bash
make
cp filemgr /tmp/filemgr
sudo ./filemgr            # option 16 creates users such as a_alice, m_mike, u_ursula, gary
sudo -u m_mike /tmp/filemgr
```

Run other users from the copy in `/tmp`, because a home folder is closed to
other accounts.


## Demo

1. `m_mike`: option 19 creates `report.txt`; option 21 appends a line.
2. `u_ursula`: option 20 is denied (not owner, no grant).
3. `m_mike`: option 23 gives `u_ursula` read access.
4. `u_ursula`: option 20 works; option 21 is denied (grant does not include write).
5. `gary`: option 19 is denied (guest cannot create).
6. `a_alice`: option 20 works by admin override; option 25 shows every user's powers.
7. Anyone: option 9 summarizes the log and raises an alert.

Example log lines:

```
user=u_ursula action=READ target=report.txt result=Permission denied (policy: not owner, no grant)
user=a_alice action=READ target=report.txt result=granted (admin override)
```
## Progress

- [x] File operations
- [x] Identity and access checks
- [x] Activity logging and log rotation
- [x] Log analysis with denial alerts
- [x] Real-time directory monitor (inotify)
- [x] Disk usage accounting with quota warning
- [x] Users and groups, kernel access table
- [x] Role-based policy: owners, grants, prefix roles
- [ ] Future work: file locking, root-owned policy service or Linux ACLs, append-only log

## Known limitations

- The policy is enforced by this program. Managed files are stored with open
  Linux permissions so grants can work, so someone using `cat` directly could
  bypass it. Ordinary files (options 1 to 6) are still protected by the kernel.
- The policy files and the log are plain text writable by every user, so they
  could be edited. A root-owned service, ACLs, or `chattr +a` would fix this.
- There is no file locking, so two users writing the same database at once
  could conflict.
- Creating real Linux users needs root, so in practice root creates admins.
- The inotify monitor cannot say who made a change, so those events are logged
  as user `unknown`.
- Log analysis reads only the current log file and counts the text
  "Permission denied".
- The kernel access table (option 15) uses permission bits only and ignores
  ACLs, SELinux and parent-folder permissions.
- The log lives in `/tmp/fmlog` because Ubuntu's `fs.protected_regular`
  setting blocks other users from appending to files inside `/tmp` itself.
