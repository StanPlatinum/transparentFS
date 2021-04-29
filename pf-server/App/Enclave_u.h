#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "user_types.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_PRINTSTRING_DEFINED__
#define OCALL_PRINTSTRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, Ocall_PrintString, (const char* str));
#endif
#ifndef OCALL_OPEN_HELPER_DEFINED__
#define OCALL_OPEN_HELPER_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_open_helper, (const char* path, bool create, pf_file_mode_t mode, size_t* file_size));
#endif
#ifndef OCALL_CLOSE_HELPER_DEFINED__
#define OCALL_CLOSE_HELPER_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_close_helper, (int fd));
#endif
#ifndef OCALL_PREAD_DEFINED__
#define OCALL_PREAD_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pread, (int fd, void* buf, size_t count, off_t offset));
#endif
#ifndef OCALL_PWRITE_DEFINED__
#define OCALL_PWRITE_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pwrite, (int fd, const void* buf, size_t count, off_t offset));
#endif
#ifndef OCALL_FTRUNCATE_DEFINED__
#define OCALL_FTRUNCATE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_ftruncate, (int fd, uint64_t length));
#endif

sgx_status_t g_pf_demo(sgx_enclave_id_t eid, int* retval);
sgx_status_t g_pf_open(sgx_enclave_id_t eid, pf_status_t* retval, pf_handle_t handle, const char* path, uint64_t underlying_size, pf_file_mode_t mode, bool create, const pf_key_t* key, pf_context_t** context);
sgx_status_t g_pf_read(sgx_enclave_id_t eid, pf_status_t* retval, pf_context_t* pf, uint64_t offset, void* output, size_t read_size, size_t* bytes_read);
sgx_status_t g_pf_write(sgx_enclave_id_t eid, pf_status_t* retval, pf_context_t* pf, uint64_t offset, const void* input, size_t write_size);
sgx_status_t g_pf_close(sgx_enclave_id_t eid, pf_status_t* retval, pf_context_t* pf);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
