#include <unistd.h>
#include <sys/types.h>
#include <stdint.h>
// #include "App.h"

int ocall_open_helper(const char* path, bool create, pf_file_mode_t mode, size_t* file_size) {
    int open_flag = -1;
    
    if (mode == PF_FILE_MODE_READ) {
        open_flag = O_RDONLY;
    }
    if (mode == PF_FILE_MODE_WRITE) {
        open_flag = O_WRONLY;
    }
    if (open_flag == -1) {
        printf("pf_file_mode_t mode set incorrectly. Exiting...\n");
        exit(-1);
    }
    
    if (create) {
        open_flag = O_CREAT|open_flag;
    }
    
    int fd = open(path, open_flag);
    if (fd != NULL)
        printf("open success in ocall_open_helper\n");
    else {
        perror("fopen");
        exit(-1);
    }

    struct stat st;
    fstat(fd, &st);
    *file_size = st.st_size;
    printf("file size: %d\n", *file_size);

    
    return fd;
}

void ocall_close_helper(int fd) {
    close(fd);
}


// ssize_t ocall_read(int fd, void* buf, size_t count) {
//     return read(fd, buf, count);
// }

// ssize_t ocall_write(int fd, const void* buf, size_t count) {
//     return write(fd, buf, count);
// }

ssize_t ocall_pread(int fd, void* buf, size_t count, off_t offset) {

    printf("DBG: before pread at ocall_pread\n");

    ssize_t rv = pread(fd, buf, count, offset);

    printf("DBG: after pread at ocall_pread\n");

    return rv;
}

ssize_t ocall_pwrite(int fd, const void *buf, size_t count, off_t offset) {
    ssize_t rv = pwrite(fd, buf, count, offset);

    printf("DBG: after pwrite at ocall_pwrite, rv: %d\n", rv);
    
    return rv;

}

int ocall_ftruncate(int fd, uint64_t length) {
    return ftruncate(fd, length);
}