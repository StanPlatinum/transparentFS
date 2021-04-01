#include <stdarg.h>
#include <stdio.h>

#include "Enclave.h"
#include "Enclave_t.h"

#include "string.h"

#include "TrustedPF/protected_files.h"

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
	//     pf_handle_t handle = (pf_handle_t)&output;
    // pf_status_t pfs = pf_open(handle, output_path, /*size=*/0, PF_FILE_MODE_WRITE, /*create=*/true,
    //                           wrap_key, &pf);

    return 0;
}