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
    return pread(fd, buf, count, offset);
}

ssize_t ocall_pwrite(int fd, const void *buf, size_t count, off_t offset) {
    return pwrite(fd, buf, count, offset);
}

int ocall_ftruncate(int fd, uint64_t length) {
    return ftruncate(fd, length);
}