#include <unistd.h>
#include <sys/types.h>
#include <stdint.h>



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