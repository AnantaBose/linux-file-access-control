#ifndef POLICY_H
#define POLICY_H

void policy_show_roles(void);
void policy_list_users(void);
int  policy_create_user(const char *username);
int  policy_new_file(const char *name);
int  policy_read_file(const char *name);
int  policy_write_file(const char *name, const char *text);
int  policy_delete_file(const char *name);
int  policy_grant(const char *name, const char *user, const char *powers);
int  policy_revoke(const char *name, const char *user);
void policy_file_report(const char *name);

#endif
