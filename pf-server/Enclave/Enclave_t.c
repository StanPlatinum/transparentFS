#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_g_pf_demo(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_g_pf_demo_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_g_pf_demo_t* ms = SGX_CAST(ms_g_pf_demo_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = g_pf_demo();


	return status;
}

static sgx_status_t SGX_CDECL sgx_g_pf_open(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_g_pf_open_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_g_pf_open_t* ms = SGX_CAST(ms_g_pf_open_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_path = ms->ms_path;
	size_t _len_path = 256;
	char* _in_path = NULL;
	const pf_key_t* _tmp_key = ms->ms_key;
	size_t _len_key = 16;
	pf_key_t* _in_key = NULL;
	pf_context_t** _tmp_context = ms->ms_context;
	size_t _len_context = sizeof(pf_context_t*);
	pf_context_t** _in_context = NULL;

	CHECK_UNIQUE_POINTER(_tmp_path, _len_path);
	CHECK_UNIQUE_POINTER(_tmp_key, _len_key);
	CHECK_UNIQUE_POINTER(_tmp_context, _len_context);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_path != NULL && _len_path != 0) {
		if ( _len_path % sizeof(*_tmp_path) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_path = (char*)malloc(_len_path);
		if (_in_path == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_path, _len_path, _tmp_path, _len_path)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_key != NULL && _len_key != 0) {
		_in_key = (pf_key_t*)malloc(_len_key);
		if (_in_key == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_key, _len_key, _tmp_key, _len_key)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_context != NULL && _len_context != 0) {
		if ( _len_context % sizeof(*_tmp_context) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_context = (pf_context_t**)malloc(_len_context)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_context, 0, _len_context);
	}

	ms->ms_retval = g_pf_open(ms->ms_handle, (const char*)_in_path, ms->ms_underlying_size, ms->ms_mode, ms->ms_create, (const pf_key_t*)_in_key, _in_context);
	if (_in_context) {
		if (memcpy_s(_tmp_context, _len_context, _in_context, _len_context)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_path) free(_in_path);
	if (_in_key) free(_in_key);
	if (_in_context) free(_in_context);
	return status;
}

static sgx_status_t SGX_CDECL sgx_g_pf_read(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_g_pf_read_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_g_pf_read_t* ms = SGX_CAST(ms_g_pf_read_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	pf_context_t* _tmp_pf = ms->ms_pf;
	void* _tmp_output = ms->ms_output;
	size_t _len_output = 100;
	void* _in_output = NULL;
	size_t* _tmp_bytes_read = ms->ms_bytes_read;

	CHECK_UNIQUE_POINTER(_tmp_output, _len_output);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_output != NULL && _len_output != 0) {
		if ((_in_output = (void*)malloc(_len_output)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_output, 0, _len_output);
	}

	ms->ms_retval = g_pf_read(_tmp_pf, ms->ms_offset, _in_output, ms->ms_read_size, _tmp_bytes_read);
	if (_in_output) {
		if (memcpy_s(_tmp_output, _len_output, _in_output, _len_output)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_output) free(_in_output);
	return status;
}

static sgx_status_t SGX_CDECL sgx_g_pf_write(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_g_pf_write_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_g_pf_write_t* ms = SGX_CAST(ms_g_pf_write_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	pf_context_t* _tmp_pf = ms->ms_pf;
	const void* _tmp_input = ms->ms_input;
	size_t _len_input = 100;
	void* _in_input = NULL;

	CHECK_UNIQUE_POINTER(_tmp_input, _len_input);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_input != NULL && _len_input != 0) {
		_in_input = (void*)malloc(_len_input);
		if (_in_input == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_input, _len_input, _tmp_input, _len_input)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = g_pf_write(_tmp_pf, ms->ms_offset, (const void*)_in_input, ms->ms_write_size);

err:
	if (_in_input) free(_in_input);
	return status;
}

static sgx_status_t SGX_CDECL sgx_g_pf_close(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_g_pf_close_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_g_pf_close_t* ms = SGX_CAST(ms_g_pf_close_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	pf_context_t* _tmp_pf = ms->ms_pf;



	ms->ms_retval = g_pf_close(_tmp_pf);


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[5];
} g_ecall_table = {
	5,
	{
		{(void*)(uintptr_t)sgx_g_pf_demo, 0, 0},
		{(void*)(uintptr_t)sgx_g_pf_open, 0, 0},
		{(void*)(uintptr_t)sgx_g_pf_read, 0, 0},
		{(void*)(uintptr_t)sgx_g_pf_write, 0, 0},
		{(void*)(uintptr_t)sgx_g_pf_close, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[6][5];
} g_dyn_entry_table = {
	6,
	{
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL Ocall_PrintString(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_Ocall_PrintString_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_PrintString_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_PrintString_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_PrintString_t));
	ocalloc_size -= sizeof(ms_Ocall_PrintString_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_open_helper(int* retval, const char* path, bool create, pf_file_mode_t mode, size_t* file_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_path = path ? strlen(path) + 1 : 0;
	size_t _len_file_size = sizeof(size_t);

	ms_ocall_open_helper_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_open_helper_t);
	void *__tmp = NULL;

	void *__tmp_file_size = NULL;

	CHECK_ENCLAVE_POINTER(path, _len_path);
	CHECK_ENCLAVE_POINTER(file_size, _len_file_size);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (path != NULL) ? _len_path : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (file_size != NULL) ? _len_file_size : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_open_helper_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_open_helper_t));
	ocalloc_size -= sizeof(ms_ocall_open_helper_t);

	if (path != NULL) {
		ms->ms_path = (const char*)__tmp;
		if (_len_path % sizeof(*path) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, path, _len_path)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_path);
		ocalloc_size -= _len_path;
	} else {
		ms->ms_path = NULL;
	}
	
	ms->ms_create = create;
	ms->ms_mode = mode;
	if (file_size != NULL) {
		ms->ms_file_size = (size_t*)__tmp;
		__tmp_file_size = __tmp;
		if (_len_file_size % sizeof(*file_size) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_file_size, 0, _len_file_size);
		__tmp = (void *)((size_t)__tmp + _len_file_size);
		ocalloc_size -= _len_file_size;
	} else {
		ms->ms_file_size = NULL;
	}
	
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (file_size) {
			if (memcpy_s((void*)file_size, _len_file_size, __tmp_file_size, _len_file_size)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_close_helper(int fd)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_close_helper_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_close_helper_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_close_helper_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_close_helper_t));
	ocalloc_size -= sizeof(ms_ocall_close_helper_t);

	ms->ms_fd = fd;
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pread(ssize_t* retval, int fd, void* buf, size_t count, off_t offset)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = count;

	ms_ocall_pread_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pread_t);
	void *__tmp = NULL;

	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pread_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pread_t));
	ocalloc_size -= sizeof(ms_ocall_pread_t);

	ms->ms_fd = fd;
	if (buf != NULL) {
		ms->ms_buf = (void*)__tmp;
		__tmp_buf = __tmp;
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	ms->ms_count = count;
	ms->ms_offset = offset;
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pwrite(ssize_t* retval, int fd, const void* buf, size_t count, off_t offset)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = count;

	ms_ocall_pwrite_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pwrite_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pwrite_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pwrite_t));
	ocalloc_size -= sizeof(ms_ocall_pwrite_t);

	ms->ms_fd = fd;
	if (buf != NULL) {
		ms->ms_buf = (const void*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, buf, _len_buf)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	ms->ms_count = count;
	ms->ms_offset = offset;
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_ftruncate(int* retval, int fd, uint64_t length)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_ftruncate_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_ftruncate_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_ftruncate_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_ftruncate_t));
	ocalloc_size -= sizeof(ms_ocall_ftruncate_t);

	ms->ms_fd = fd;
	ms->ms_length = length;
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

