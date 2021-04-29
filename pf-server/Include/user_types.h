/*
 * Copyright (C) 2011-2017 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef USER_TYPES_H_
#define USER_TYPES_H_

#include <stdbool.h>

#include <unistd.h>
#include <sys/types.h>


/* User defined types */

typedef enum _pf_status_t {
    PF_STATUS_SUCCESS              = 0,
    PF_STATUS_UNKNOWN_ERROR        = -1,
    PF_STATUS_UNINITIALIZED        = -2,
    PF_STATUS_INVALID_PARAMETER    = -3,
    PF_STATUS_INVALID_MODE         = -4,
    PF_STATUS_NO_MEMORY            = -5,
    PF_STATUS_INVALID_VERSION      = -6,
    PF_STATUS_INVALID_HEADER       = -7,
    PF_STATUS_INVALID_PATH         = -8,
    PF_STATUS_MAC_MISMATCH         = -9,
    PF_STATUS_NOT_IMPLEMENTED      = -10,
    PF_STATUS_CALLBACK_FAILED      = -11,
    PF_STATUS_PATH_TOO_LONG        = -12,
    PF_STATUS_RECOVERY_NEEDED      = -13,
    PF_STATUS_FLUSH_ERROR          = -14,
    PF_STATUS_CRYPTO_ERROR         = -15,
    PF_STATUS_CORRUPTED            = -16,
    PF_STATUS_WRITE_TO_DISK_FAILED = -17,
} pf_status_t;

/*! Opaque file handle type, interpreted by callbacks as necessary */
typedef void* pf_handle_t;

/*! PF open modes */
typedef enum _pf_file_mode_t {
    PF_FILE_MODE_READ  = 1,
    PF_FILE_MODE_WRITE = 2,
} pf_file_mode_t;

/*! Size of the AES-GCM encryption key */
#define PF_KEY_SIZE 16

typedef uint8_t pf_key_t[PF_KEY_SIZE];



/*! Context representing an open protected file */
typedef struct pf_context pf_context_t;



#endif