#ifndef USERS_H
#define USERS_H

void list_users(void);
void list_groups(void);
void show_user_groups(const char *username);
void access_matrix(const char *path);
int  create_user(const char *username);

#endif
