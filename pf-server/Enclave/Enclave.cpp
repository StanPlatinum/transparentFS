#include <stdarg.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Enclave.h"
#include "Enclave_t.h"


const pf_key_t* preset_user_pf_key;

/* re-define printf inside enclave */
void printf(const char *fmt, ...){
	char buf[BUFSIZ] = {'\0'};
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);
	Ocall_PrintString(buf);
}

int g_pf_demo(void){
    // a short demo to operate on graphene protected fs totally within an enclave

    pf_key_t default_key = {0};
    sgx_status_t rv;
    pf_status_t grv;
    int fd;
    size_t file_size;
    const char* default_path = "data/write_sec.txt";
    char* content = "a secret string";
    size_t content_len = strlen(content);

    
    pf_context_t* context_p;
    pf_context_t** context_pp = &context_p;
    pf_handle_t g_file_handle = (pf_handle_t) &fd;
    
    // write content to a protected file
    rv = ocall_open_helper(&fd, default_path, true, PF_FILE_MODE_WRITE, &file_size);
    printf("fd: %d, size: %d \n", fd, file_size);


    // APIs starting with g_* are processed within the enclave
    grv = g_pf_open(g_file_handle, default_path, file_size, PF_FILE_MODE_WRITE, true, &default_key, context_pp);
    grv = g_pf_write(*context_pp, 0, content, content_len);
    grv = g_pf_close(*context_pp);

    rv = ocall_close_helper(fd);

    rv = ocall_open_helper(&fd, default_path, false, PF_FILE_MODE_READ, &file_size);
    printf("fd: %d, size: %d \n", fd, file_size);
    

    // create a buffer to read
    char read_buffer[1000] = {0};
    size_t bytes_read;
    grv = g_pf_open(g_file_handle, default_path, file_size, PF_FILE_MODE_READ, false, &default_key, context_pp);
    grv = g_pf_read(*context_pp, 0, read_buffer, content_len, &bytes_read);
    printf("The content of the pf is: \n%s\n", read_buffer);
    grv = g_pf_close(*context_pp);

	return 0;
}


#include "g_protected_files.c"

// TODO: file truncation
pf_status_t pf_set_size(pf_context_t* pf, uint64_t size) {
    if (!g_initialized)
        return PF_STATUS_UNINITIALIZED;

    if (!(pf->mode & PF_FILE_MODE_WRITE))
        return PF_STATUS_INVALID_MODE;

    if (size == pf->encrypted_part_plain.size)
        return PF_STATUS_SUCCESS;

    if (size > pf->encrypted_part_plain.size) {
        // extend the file
        pf->offset = pf->encrypted_part_plain.size;
        DEBUG_PF("extending the file from %lu to %lu\n", pf->offset, size);
        if (ipf_write(pf, NULL, size - pf->offset) != size - pf->offset)
            return pf->last_error;

        return PF_STATUS_SUCCESS;
    }

    return PF_STATUS_NOT_IMPLEMENTED;
}

pf_status_t g_pf_open(pf_handle_t handle, const char* path, uint64_t underlying_size,
                    pf_file_mode_t mode, bool create, const pf_key_t* key, pf_context_t** context) {

	printf("handle: %p\n", handle);
	printf("path: %s\n", path);
	printf("underlying_size: %d\n", underlying_size);
	printf("mode: %d\n", mode);
	printf("key the 15th byte: %d\n", (*key)[14]);

    pf_status_t status;
     
	pf_context_t* ret = ipf_open(path, mode, create, handle, underlying_size, key, &status);
    DEBUG_PF("DBG: xxx of g_pf_open\n");
	*context = ret;
	DEBUG_PF("DBG: end of g_pf_open\n");
	
	return status;
}

pf_status_t g_pf_read(pf_context_t* pf, uint64_t offset, void* output, size_t read_size,
                    size_t* bytes_read) {

	DEBUG_PF("DBG: begin of g_pf_read\n");
	DEBUG_PF("DBG: begin of g_pf_read, path: %s\n", pf->encrypted_part_plain.path);

    if (!g_initialized)
        return PF_STATUS_UNINITIALIZED;

    if (!read_size) {
        *bytes_read = 0;
        return PF_STATUS_SUCCESS;
    }

    if (!ipf_seek(pf, offset))
        return pf->last_error;

    if (pf->end_of_file || pf->offset == pf->encrypted_part_plain.size) {
        pf->end_of_file = true;
        *bytes_read = 0;
        return PF_STATUS_SUCCESS;
    }

    size_t bytes = ipf_read(pf, output, read_size);
	DEBUG_PF("DBG: output: %s\n", output);
    if (!bytes)
        return pf->last_error;

    *bytes_read = bytes;
    return PF_STATUS_SUCCESS;
}

pf_status_t g_pf_write(pf_context_t* pf, uint64_t offset, const void* input, size_t write_size) {
    if (!g_initialized)
        return PF_STATUS_UNINITIALIZED;

    if (!ipf_seek(pf, offset))
        return pf->last_error;

    if (ipf_write(pf, input, write_size) != write_size)
        return pf->last_error;
    return PF_STATUS_SUCCESS;
}

pf_status_t g_pf_close(pf_context_t* pf) {
    if (!g_initialized)
        return PF_STATUS_UNINITIALIZED;

    if (ipf_close(pf))
        return PF_STATUS_SUCCESS;
    return pf->last_error;
}