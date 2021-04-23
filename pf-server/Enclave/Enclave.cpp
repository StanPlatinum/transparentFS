#include <stdarg.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Enclave.h"
#include "Enclave_t.h"


/* re-define printf inside enclave */
void printf(const char *fmt, ...){
	char buf[BUFSIZ] = {'\0'};
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);
	Ocall_PrintString(buf);
}

int pf_demo_processing(void){
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
	context = &ret;
	DEBUG_PF("DBG: end of g_pf_open\n");
	
	return status;
}

pf_status_t g_pf_read(pf_context_t* pf, uint64_t offset, size_t size, void* output,
                    size_t* bytes_read) {

	DEBUG_PF("DBG: begin of g_pf_read\n");

    if (!g_initialized)
        return PF_STATUS_UNINITIALIZED;

    if (!size) {
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

    size_t bytes = ipf_read(pf, output, size);
    if (!bytes)
        return pf->last_error;

    *bytes_read = bytes;
    return PF_STATUS_SUCCESS;
}