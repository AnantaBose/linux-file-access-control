# Linux File Management & Access Control System with Activity Logging

A C program built on real Linux POSIX syscalls that manages files,
enforces access control using actual Linux user permissions, and
logs every action performed.

## Concept

Real Linux user accounts (not custom login) act as the "users" of
the system. The kernel's own permission system (owner/group/other,
chmod/chown) enforces who can do what — the program reads and
displays this, and logs every attempted operation.

## Progress

- [x] `create_file()` — using `open()` with `O_CREAT | O_EXCL`
- [x] `delete_file()` — using `unlink()`
- [ ] `stat()` — read file metadata/permissions
- [ ] `chmod()`/`chown()` — change permissions/ownership
- [ ] Activity logging to `logs/activity.log`
- [ ] Directory listing with permissions (`ls -l` style)
- [ ] Menu-driven interface

## Build & Run

\`\`\`bash
gcc test.c -o test
./test
\`\`\`

(Will be updated to `make`/`./filemgr` once the project is split
into proper modules.)

## Concepts used so far

- File descriptors and the `open()`/`close()` lifecycle
- `errno` and `perror()` for syscall error handling
- `O_CREAT` / `O_EXCL` flags and why atomic create-vs-overwrite
  behavior matters for a file manager
- `unlink()` and why Linux calls file deletion "unlinking"
  (filenames are links to data, not the data itself)# linux-file-access-control
