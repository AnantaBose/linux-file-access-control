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
- [x] `show_file_info()` — using `stat()` for size and owner
- [x] `show_permissions()` — decoding `st_mode` bits for owner/group/other
- [x] `change_permissions()` — using `chmod()`
- [x] `list_directory()` — using `opendir()`/`readdir()`/`closedir()`
- [ ] `chown()` — change file ownership
- [ ] Real permission-based access control (using real Linux users, `access()`)
- [ ] Activity logging to `logs/activity.log`
- [ ] Menu-driven interface tying everything together

## Concepts used so far

- File descriptors and the `open()`/`close()` lifecycle
- `errno` and `perror()` for syscall error handling
- `O_CREAT` / `O_EXCL` flags and why atomic create-vs-overwrite behavior
  matters for a file manager
- `unlink()` and why Linux calls file deletion "unlinking" (filenames
  are links to data, not the data itself)
- Inodes and `stat()` — how the kernel stores file metadata separately
  from file content
- Pointers and the "give me a box, I'll fill it in" pattern (`&file_info`)
- Bitwise AND (`&`) for checking individual permission flags in `st_mode`
- `chmod()` for changing permission bits, and verifying the change by
  re-reading the file's real state afterward
- Directory iteration with `opendir()`/`readdir()`/`closedir()`

## Build & Run

\`\`\`bash
gcc test.c -o test
./test
\`\`\`

(Will be updated to `make`/`./filemgr` once the project is split
into proper modules.)

