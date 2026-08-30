#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

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

int main() {
    if (create_file("hello.txt") == 0) {
        printf("Success!\n");
    } else {
        printf("Failed.\n");
    }

    if (delete_file("hello.txt") == 0) {
        printf("Deleted!\n");
    } else {
        printf("Delete Failed.\n");
    }
    return 0;
}
