#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "user_types.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

int g_pf_demo(void);
pf_status_t g_pf_open(pf_handle_t handle, const char* path, uint64_t underlying_size, pf_file_mode_t mode, bool create, const pf_key_t* key, pf_context_t** context);
pf_status_t g_pf_read(pf_context_t* pf, uint64_t offset, void* output, size_t read_size, size_t* bytes_read);
pf_status_t g_pf_write(pf_context_t* pf, uint64_t offset, const void* input, size_t write_size);
pf_status_t g_pf_close(pf_context_t* pf);

sgx_status_t SGX_CDECL Ocall_PrintString(const char* str);
sgx_status_t SGX_CDECL ocall_open_helper(int* retval, const char* path, bool create, pf_file_mode_t mode, size_t* file_size);
sgx_status_t SGX_CDECL ocall_close_helper(int fd);
sgx_status_t SGX_CDECL ocall_pread(ssize_t* retval, int fd, void* buf, size_t count, off_t offset);
sgx_status_t SGX_CDECL ocall_pwrite(ssize_t* retval, int fd, const void* buf, size_t count, off_t offset);
sgx_status_t SGX_CDECL ocall_ftruncate(int* retval, int fd, uint64_t length);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
