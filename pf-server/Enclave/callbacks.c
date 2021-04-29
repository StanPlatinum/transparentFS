#include <errno.h>

#include "g_protected_files.h"

/* Callbacks for protected files handling */
static pf_status_t cb_read(pf_handle_t handle, void* buffer, uint64_t offset, size_t size) {
    int fd = *(int*)handle;
    size_t buffer_offset = 0;
    size_t to_read = size;

    while (to_read > 0) {
        ssize_t read;

        printf("DBG: before ocall_pread at cb_read\n");

        sgx_status_t ret = ocall_pread(&read, fd, buffer + buffer_offset, to_read, offset + buffer_offset);
        printf("DBG: after ocall_pread at cb_read\n");

        if (read == -EINTR)
            continue;

        if (read < 0 || ret < 0) {
            printf("cb_read(%d, %p, %lu, %lu): read failed: %ld\n", fd, buffer, offset,
                      size, read);
            return PF_STATUS_CALLBACK_FAILED;
        }

        /* EOF is an error condition, we want to read exactly `size` bytes */
        if (read == 0) {
            printf("cb_read(%d, %p, %lu, %lu): EOF\n", fd, buffer, offset, size);
            return PF_STATUS_CALLBACK_FAILED;
        }

        to_read -= read;
        buffer_offset += read;
    }
    return PF_STATUS_SUCCESS;
}

static pf_status_t cb_write(pf_handle_t handle, const void* buffer, uint64_t offset, size_t size) {
    int fd = *(int*)handle;
    size_t buffer_offset = 0;
    size_t to_write = size;
    while (to_write > 0) {
        ssize_t written;
        sgx_status_t ret = ocall_pwrite(&written, fd, buffer + buffer_offset, to_write,
                                       offset + buffer_offset);
        if (written == -EINTR)
            continue;

        if (written < 0 || ret < 0) {
            printf("cb_write(%d, %p, %lu, %lu): write failed: %ld\n", fd, buffer, offset,
                      size, written);
            return PF_STATUS_CALLBACK_FAILED;
        }

        /* EOF is an error condition, we want to write exactly `size` bytes */
        if (written == 0) {
            printf("cb_write(%d, %p, %lu, %lu): EOF\n", fd, buffer, offset, size);
            return PF_STATUS_CALLBACK_FAILED;
        }

        to_write -= written;
        buffer_offset += written;
    }
    return PF_STATUS_SUCCESS;
}

static pf_status_t cb_truncate(pf_handle_t handle, uint64_t size) {
    int fd = *(int*)handle;
    int rv;
    sgx_status_t ret = ocall_ftruncate(&rv, fd, size);
    if (ret < 0) {
        printf("cb_truncate(%d, %lu): ocall failed: %d\n", fd, size, ret);
        return PF_STATUS_CALLBACK_FAILED;
    }
    return PF_STATUS_SUCCESS;
}


// #ifdef DEBUG
// static void cb_debug(const char* msg) {
//     log_debug("%s", msg);
// }
// #endif

//WL: instantiate lib_AESGCMEncrypt, lib_AESGCMDecrypt
#include "sgx_trts.h"
#include "sgx_tcrypto.h"

static pf_status_t cb_aes_gcm_encrypt(const pf_key_t* key, const pf_iv_t* iv, const void* aad,
                                      size_t aad_size, const void* input, size_t input_size,
                                      void* output, pf_mac_t* mac) {

    sgx_status_t ret = sgx_rijndael128GCM_encrypt(key, (const uint8_t *) input, (uint32_t) input_size,  
                                      (uint8_t *) output, (const uint8_t *) iv, 12, (const uint8_t *) aad, (uint32_t) aad_size,
                                      mac);
    if (ret != 0) {
        printf("sgx_rijndael128GCM_encrypt failed: %d\n", ret);
        return PF_STATUS_CALLBACK_FAILED;
    }
    return PF_STATUS_SUCCESS;
}

static pf_status_t cb_aes_gcm_decrypt(const pf_key_t* key, const pf_iv_t* iv, const void* aad,
                                      size_t aad_size, const void* input, size_t input_size,
                                      void* output, const pf_mac_t* mac) {
    sgx_status_t ret = sgx_rijndael128GCM_decrypt(key, (const uint8_t *) input, (uint32_t) input_size,  
                                      (uint8_t *) output, (const uint8_t *) iv, 12, (const uint8_t *) aad, (uint32_t) aad_size,
                                      mac);

    if (ret != 0) {
        printf("sgx_rijndael128GCM_decrypt failed: %d\n", ret);
        return PF_STATUS_CALLBACK_FAILED;
    }
    return PF_STATUS_SUCCESS;
}


//WL: instantiate randombitsread

/*!
 * \brief Low-level wrapper around RDRAND instruction (get hardware-generated random value).
 */
static inline uint32_t rdrand(void) {
    uint32_t ret;
    asm volatile(
        "1: .byte 0x0f, 0xc7, 0xf0\n" /* RDRAND %EAX */
        "jnc 1b\n"
        :"=a"(ret)
        :: "cc");
    return ret;
}

int g_DkRandomBitsRead(void* buffer, size_t size) {
    uint32_t rand;
    for (size_t i = 0; i < size; i += sizeof(rand)) {
        rand = rdrand();
        memcpy(buffer + i, &rand, MIN(sizeof(rand), size - i));
    }
    return 0;
}

static pf_status_t cb_random(uint8_t* buffer, size_t size) {
    int ret = g_DkRandomBitsRead(buffer, size);
    if (ret < 0) {
        printf("_DkRandomBitsRead failed: %d\n", ret);
        return PF_STATUS_CALLBACK_FAILED;
    }
    return PF_STATUS_SUCCESS;
}