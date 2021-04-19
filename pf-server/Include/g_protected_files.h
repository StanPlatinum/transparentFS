#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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


/*! Size of the AES-GCM encryption key */
#define PF_KEY_SIZE 16

/*! Size of IV for AES-GCM */
#define PF_IV_SIZE 12

/*! Size of MAC fields */
#define PF_MAC_SIZE 16

typedef uint8_t pf_iv_t[PF_IV_SIZE];
typedef uint8_t pf_mac_t[PF_MAC_SIZE];
typedef uint8_t pf_key_t[PF_KEY_SIZE];
typedef uint8_t pf_keyid_t[32]; /* key derivation material */

#define PF_NODE_SIZE 4096U

typedef enum _pf_file_mode_t {
    PF_FILE_MODE_READ  = 1,
    PF_FILE_MODE_WRITE = 2,
} pf_file_mode_t;

/*! Opaque file handle type, interpreted by callbacks as necessary */
typedef void* pf_handle_t;

/*! Context representing an open protected file */
typedef struct pf_context pf_context_t;