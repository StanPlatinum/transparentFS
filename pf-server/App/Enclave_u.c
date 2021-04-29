#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_g_pf_demo_t {
	int ms_retval;
} ms_g_pf_demo_t;

typedef struct ms_g_pf_open_t {
	pf_status_t ms_retval;
	pf_handle_t ms_handle;
	const char* ms_path;
	uint64_t ms_underlying_size;
	pf_file_mode_t ms_mode;
	bool ms_create;
	const pf_key_t* ms_key;
	pf_context_t** ms_context;
} ms_g_pf_open_t;

typedef struct ms_g_pf_read_t {
	pf_status_t ms_retval;
	pf_context_t* ms_pf;
	uint64_t ms_offset;
	void* ms_output;
	size_t ms_read_size;
	size_t* ms_bytes_read;
} ms_g_pf_read_t;

typedef struct ms_g_pf_write_t {
	pf_status_t ms_retval;
	pf_context_t* ms_pf;
	uint64_t ms_offset;
	const void* ms_input;
	size_t ms_write_size;
} ms_g_pf_write_t;

typedef struct ms_g_pf_close_t {
	pf_status_t ms_retval;
	pf_context_t* ms_pf;
} ms_g_pf_close_t;

typedef struct ms_Ocall_PrintString_t {
	const char* ms_str;
} ms_Ocall_PrintString_t;

typedef struct ms_ocall_open_helper_t {
	int ms_retval;
	const char* ms_path;
	bool ms_create;
	pf_file_mode_t ms_mode;
	size_t* ms_file_size;
} ms_ocall_open_helper_t;

typedef struct ms_ocall_close_helper_t {
	int ms_fd;
} ms_ocall_close_helper_t;

typedef struct ms_ocall_pread_t {
	ssize_t ms_retval;
	int ms_fd;
	void* ms_buf;
	size_t ms_count;
	off_t ms_offset;
} ms_ocall_pread_t;

typedef struct ms_ocall_pwrite_t {
	ssize_t ms_retval;
	int ms_fd;
	const void* ms_buf;
	size_t ms_count;
	off_t ms_offset;
} ms_ocall_pwrite_t;

typedef struct ms_ocall_ftruncate_t {
	int ms_retval;
	int ms_fd;
	uint64_t ms_length;
} ms_ocall_ftruncate_t;

static sgx_status_t SGX_CDECL Enclave_Ocall_PrintString(void* pms)
{
	ms_Ocall_PrintString_t* ms = SGX_CAST(ms_Ocall_PrintString_t*, pms);
	Ocall_PrintString(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_open_helper(void* pms)
{
	ms_ocall_open_helper_t* ms = SGX_CAST(ms_ocall_open_helper_t*, pms);
	ms->ms_retval = ocall_open_helper(ms->ms_path, ms->ms_create, ms->ms_mode, ms->ms_file_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_close_helper(void* pms)
{
	ms_ocall_close_helper_t* ms = SGX_CAST(ms_ocall_close_helper_t*, pms);
	ocall_close_helper(ms->ms_fd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pread(void* pms)
{
	ms_ocall_pread_t* ms = SGX_CAST(ms_ocall_pread_t*, pms);
	ms->ms_retval = ocall_pread(ms->ms_fd, ms->ms_buf, ms->ms_count, ms->ms_offset);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pwrite(void* pms)
{
	ms_ocall_pwrite_t* ms = SGX_CAST(ms_ocall_pwrite_t*, pms);
	ms->ms_retval = ocall_pwrite(ms->ms_fd, ms->ms_buf, ms->ms_count, ms->ms_offset);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_ftruncate(void* pms)
{
	ms_ocall_ftruncate_t* ms = SGX_CAST(ms_ocall_ftruncate_t*, pms);
	ms->ms_retval = ocall_ftruncate(ms->ms_fd, ms->ms_length);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[6];
} ocall_table_Enclave = {
	6,
	{
		(void*)Enclave_Ocall_PrintString,
		(void*)Enclave_ocall_open_helper,
		(void*)Enclave_ocall_close_helper,
		(void*)Enclave_ocall_pread,
		(void*)Enclave_ocall_pwrite,
		(void*)Enclave_ocall_ftruncate,
	}
};
sgx_status_t g_pf_demo(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_g_pf_demo_t ms;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t g_pf_open(sgx_enclave_id_t eid, pf_status_t* retval, pf_handle_t handle, const char* path, uint64_t underlying_size, pf_file_mode_t mode, bool create, const pf_key_t* key, pf_context_t** context)
{
	sgx_status_t status;
	ms_g_pf_open_t ms;
	ms.ms_handle = handle;
	ms.ms_path = path;
	ms.ms_underlying_size = underlying_size;
	ms.ms_mode = mode;
	ms.ms_create = create;
	ms.ms_key = key;
	ms.ms_context = context;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t g_pf_read(sgx_enclave_id_t eid, pf_status_t* retval, pf_context_t* pf, uint64_t offset, void* output, size_t read_size, size_t* bytes_read)
{
	sgx_status_t status;
	ms_g_pf_read_t ms;
	ms.ms_pf = pf;
	ms.ms_offset = offset;
	ms.ms_output = output;
	ms.ms_read_size = read_size;
	ms.ms_bytes_read = bytes_read;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t g_pf_write(sgx_enclave_id_t eid, pf_status_t* retval, pf_context_t* pf, uint64_t offset, const void* input, size_t write_size)
{
	sgx_status_t status;
	ms_g_pf_write_t ms;
	ms.ms_pf = pf;
	ms.ms_offset = offset;
	ms.ms_input = input;
	ms.ms_write_size = write_size;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t g_pf_close(sgx_enclave_id_t eid, pf_status_t* retval, pf_context_t* pf)
{
	sgx_status_t status;
	ms_g_pf_close_t ms;
	ms.ms_pf = pf;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

