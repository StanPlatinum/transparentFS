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


pf_status_t g_pf_open(pf_handle_t handle, const char* path, uint64_t underlying_size,
                    pf_file_mode_t mode, bool create, const pf_key_t* key, pf_context_t** context) {

	printf("handle: %p\n", handle);
	printf("path: %s\n", path);
	printf("underlying_size: %d\n", underlying_size);
	printf("mode: %d\n", mode);
	printf("key the 15th byte: %d\n", (*key)[14]);

    pf_status_t status;
    // *context = ipf_open(path, mode, create, handle, underlying_size, key, &status);
    return status;
}
