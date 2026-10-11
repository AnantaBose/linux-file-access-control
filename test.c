#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <pwd.h>
#include <dirent.h>

int create_file(const char *path) {
    int fd = open(path, O_CREAT | O_EXCL |O_WRONLY, 0644);

    if (fd == -1) {
        perror("open");
        return -1;
    }

    close(fd);
    return 0;
}

int delete_file(const char *path){
	int result = unlink(path);
	if (result == -1){
	perror("unlink");
	return -1;
	}
	
	return 0;
}

int show_file_info(const char *path){
	struct stat file_info;
	int result = stat(path,&file_info);
	
	if (result == -1){
		perror("stat");
		return -1;
	}
	printf("Size: %ld bytes\n", file_info.st_size);
	printf("Owner UID: %d\n", file_info.st_uid);

	struct passwd *pw = getpwuid(file_info.st_uid);
	if (pw != NULL) {	
		printf("Owner: %s\n", pw->pw_name);
	}

	return 0;
}

void show_permissions(const char *path) {
	struct stat file_info;

	int result = stat (path, &file_info);
	if (result == -1){
		perror("stat");
		return;
	}
	
	if (file_info.st_mode & S_IRUSR){
	printf("Owner can read\n");
	}
	
	if (file_info.st_mode & S_IWUSR){
        printf("Owner can write\n");
        }

	if (file_info.st_mode & S_IXUSR){
        printf("Owner can execute\n");
        }

	if (file_info.st_mode & S_IRGRP) printf("Group can read\n");
	if (file_info.st_mode & S_IWGRP) printf("Group can write\n");
	if (file_info.st_mode & S_IXGRP) printf("Group can execute\n");

	if (file_info.st_mode & S_IROTH) printf("Other can read\n");
	if (file_info.st_mode & S_IWOTH) printf("Other can write\n");
	if (file_info.st_mode & S_IXOTH) printf("Other can execute\n");
 
}

int change_permissions(const char *path, mode_t mode){
	int result = chmod(path, mode);
	if(result == -1){
		perror("chmod");
		return -1;
	}
	return 0;
}

void list_directory(const char *path){
	DIR *dir = opendir(path);
	if (dir == NULL){

		perror("opendir");
		return;
	}
	struct dirent *entry;
	while((entry = readdir(dir)) != NULL){
		printf("%s\n", entry->d_name);
	}

	closedir(dir);
}

void show_identity(){

	uid_t uid = getuid();
	struct passwd *pw = getpwuid(uid);

	if (pw == NULL) {
		printf("Unknown user (UID %d)\n", uid);
		return;

	}
	printf("Running as: %s (UID %d)\n", pw->pw_name, uid);

}

int check_access( const char *path, int mode){
	int result = access(path, mode);
	
	if (result == -1){
		perror("access");
		return -1;
	}

	return 0;

}

int main(int argc, char *argv[]) {
	if(argc < 2){
		printf("Usage: %s <file>\n",argv[0]);
		return 1;

	}
	show_identity();

	printf( "Can read? %s\n", check_access(argv[1], R_OK) == 0 ? "yes" : "no");
	printf( "Can write? %s\n", check_access(argv[1], W_OK) == 0 ? "yes" : "no");
	printf( "Can exec? %s\n", check_access(argv[1], X_OK) == 0? "yes" : "no");

	return 0;
}

