#ifndef PROTECTED_FILES_H_
#define PROTECTED_FILES_H_

#include <limits.h>
#include "assert.h"


#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "user_types.h"

//api.h
////////////////////////////////////

#ifdef __cplusplus
extern "C"
{
#endif

// C header here
#include "g_api.h"

#ifdef __cplusplus
}
#endif


//list.h
////////////////////////////////////


// #ifdef DEBUG
// #include <assert.h>
// #define LIST_ASSERT(COND) assert(COND)
// #else
// #define LIST_ASSERT(COND)
// #endif

// #define LIST_TYPE(STRUCT_NAME)  struct list_head##_##STRUCT_NAME
// #define LISTP_TYPE(STRUCT_NAME) struct listp##_##STRUCT_NAME

// /* Declare the enclosing struct for convenience, on
//  * the assumption that this is primarily used in structure
//  * definitions, and harmless if duplicated. */
// #define DEFINE_LIST(STRUCT_NAME)  \
//     struct STRUCT_NAME;           \
//     LIST_TYPE(STRUCT_NAME) {      \
//         struct STRUCT_NAME* next; \
//         struct STRUCT_NAME* prev; \
//     }

// /* We use LISTP for pointers to a list.  This project only really needs
//  * doubly-linked lists.  We used hlists to get a single pointer for more
//  * efficient hash tables, but they were still effectively doubly-linked
//  * lists. */
// #define DEFINE_LISTP(STRUCT)  \
//     LISTP_TYPE(STRUCT) {      \
//         struct STRUCT* first; \
//     }

// #define LISTP_INIT {NULL}

// /* A node not on a list uses NULL; on a list, you
//  * store self pointers */
// #define INIT_LIST_HEAD(OBJECT, FIELD) \
//     do {                              \
//         (OBJECT)->FIELD.next = NULL;  \
//         (OBJECT)->FIELD.prev = NULL;  \
//     } while (0)

// #define INIT_LISTP(OBJECT)      \
//     do {                        \
//         (OBJECT)->first = NULL; \
//     } while (0)

// #define LISTP_EMPTY(HEAD) ((HEAD)->first == NULL)

// #define LIST_EMPTY(NODE, FIELD) ((NODE)->FIELD.next == NULL)

// /* This helper takes 3 arguments - all should be containing structures,
//  * and the field to use for the offset to the list node */
// #define __LIST_ADD(NEW, NEXT, PREV, FIELD)       \
//     do {                                         \
//         __typeof__(NEW) __tmp_next = (NEXT);     \
//         __typeof__(NEW) __tmp_prev = (PREV);     \
//         __tmp_prev->FIELD.next     = (NEW);      \
//         __tmp_next->FIELD.prev     = (NEW);      \
//         (NEW)->FIELD.next          = __tmp_next; \
//         (NEW)->FIELD.prev          = __tmp_prev; \
//     } while (0)

// #define LIST_ADD(NEW, HEAD, FIELD) __LIST_ADD(NEW, (HEAD)->FIELD.next, HEAD, FIELD)

// #define LISTP_ADD(NEW, HEAD, FIELD)                                           \
//     do {                                                                      \
//         if ((HEAD)->first == NULL) {                                          \
//             (HEAD)->first     = (NEW);                                        \
//             (NEW)->FIELD.next = (NEW);                                        \
//             (NEW)->FIELD.prev = (NEW);                                        \
//         } else {                                                              \
//             __LIST_ADD(NEW, (HEAD)->first, (HEAD)->first->FIELD.prev, FIELD); \
//             (HEAD)->first = (NEW);                                            \
//         }                                                                     \
//     } while (0)

// /* If NODE is defined, add NEW after NODE; if not,
//  * put NEW at the front of the list */
// #define LISTP_ADD_AFTER(NEW, NODE, HEAD, FIELD) \
//     do {                                        \
//         if (NODE)                               \
//             LIST_ADD(NEW, NODE, FIELD);         \
//         else                                    \
//             LISTP_ADD(NEW, HEAD, FIELD);        \
//     } while (0)

// #define LIST_ADD_TAIL(NEW, HEAD, FIELD) __LIST_ADD(NEW, HEAD, (HEAD)->FIELD.prev, FIELD)

// #define LISTP_ADD_TAIL(NEW, HEAD, FIELD)              \
//     do {                                              \
//         if ((HEAD)->first == NULL) {                  \
//             (HEAD)->first     = (NEW);                \
//             (NEW)->FIELD.next = (NEW);                \
//             (NEW)->FIELD.prev = (NEW);                \
//         } else                                        \
//             LIST_ADD_TAIL(NEW, (HEAD)->first, FIELD); \
//     } while (0)

// /* Or deletion needs to know the list root */
// #define LISTP_DEL(NODE, HEAD, FIELD)                           \
//     do {                                                       \
//         if ((HEAD)->first == (NODE)) {                         \
//             if ((NODE)->FIELD.next == (NODE)) {                \
//                 (HEAD)->first = NULL;                          \
//             } else {                                           \
//                 (HEAD)->first = (NODE)->FIELD.next;            \
//             }                                                  \
//         }                                                      \
//         LIST_ASSERT((NODE)->FIELD.prev->FIELD.next == (NODE)); \
//         LIST_ASSERT((NODE)->FIELD.next->FIELD.prev == (NODE)); \
//         (NODE)->FIELD.prev->FIELD.next = (NODE)->FIELD.next;   \
//         (NODE)->FIELD.next->FIELD.prev = (NODE)->FIELD.prev;   \
//     } while (0)

// #define LISTP_DEL_INIT(NODE, HEAD, FIELD) \
//     do {                                  \
//         LISTP_DEL(NODE, HEAD, FIELD);     \
//         INIT_LIST_HEAD(NODE, FIELD);      \
//     } while (0)

// /* Keep vestigial TYPE and FIELD parameters to minimize disruption
//  * when switching from Linux list implementation */
// #define LISTP_FIRST_ENTRY(LISTP, TYPE, FIELD) ((LISTP)->first)

// /* New API: return last entry in list */
// #define LISTP_LAST_ENTRY(LISTP, TYPE, FIELD) ((LISTP)->first->FIELD.prev)

// /* New API: return next entry in list */
// #define LISTP_NEXT_ENTRY(NODE, LISTP, FIELD) \
//     ((NODE) == (LISTP)->first->FIELD.prev ? NULL : (NODE)->FIELD.next)

// /* New API: return previous entry in list */
// #define LISTP_PREV_ENTRY(NODE, LISTP, FIELD) ((NODE) == (LISTP)->first ? NULL : (NODE)->FIELD.prev)

// /* Vestigial - for compat with Linux list code; rename to listp?
//  */
// #define LIST_ENTRY(LISTP, TYPE, FIELD) (LISTP)

// #define LISTP_FOR_EACH_ENTRY(CURSOR, HEAD, FIELD)                       \
//     for (bool first_iter = ((CURSOR) = (HEAD)->first, !!(HEAD)->first); \
//          first_iter || (CURSOR) != (HEAD)->first;                       \
//          (CURSOR) = (CURSOR)->FIELD.next, first_iter = false)

// #define LISTP_FOR_EACH_ENTRY_REVERSE(CURSOR, HEAD, FIELD)                             \
//     for (bool first_iter =                                                            \
//              ((CURSOR) = ((HEAD)->first ? (HEAD)->first->FIELD.prev : (HEAD)->first), \
//              !!(HEAD)->first);                                                        \
//          first_iter || ((CURSOR) && (CURSOR)->FIELD.next != (HEAD)->first);           \
//          (CURSOR) = (CURSOR)->FIELD.prev, first_iter = false)

// #define LISTP_FOR_EACH_ENTRY_SAFE(CURSOR, TMP, HEAD, FIELD)                                        \
//     for (bool first_iter = ((CURSOR) = (HEAD)->first,                                              \
//                            (TMP) = ((CURSOR) ? (CURSOR)->FIELD.next : (CURSOR)), !!(HEAD)->first); \
//          (HEAD)->first &&                                                                          \
//          (first_iter || (CURSOR) != (HEAD)->first);                                                \
//          /* Handle the case where the first element was removed. */                                \
//          first_iter = first_iter && (TMP) != (CURSOR) && (HEAD)->first == (TMP), (CURSOR) = (TMP), \
//               (TMP) = (TMP)->FIELD.next)

// /* Continue safe iteration with CURSOR->next */
// #define LISTP_FOR_EACH_ENTRY_SAFE_CONTINUE(CURSOR, TMP, HEAD, FIELD)    \
//     for ((CURSOR) = (CURSOR)->FIELD.next, (TMP) = (CURSOR)->FIELD.next; \
//          (CURSOR) != (HEAD)->first && (HEAD)->first; (CURSOR) = (TMP), (TMP) = (TMP)->FIELD.next)

// /* Assertion code written in Graphene project */
// #define CHECK_LIST_HEAD(TYPE, HEAD, FIELD)                               \
//     do {                                                                 \
//         TYPE pos;                                                        \
//         LISTP_FOR_EACH_ENTRY(pos, HEAD, FIELD) {                         \
//             assert((pos->FIELD.prev != pos && pos->FIELD.next != pos) || \
//                    (pos->FIELD.prev == pos && pos->FIELD.next == pos));  \
//             assert(pos->FIELD.prev->FIELD.next == pos);                  \
//             assert(pos->FIELD.next->FIELD.prev == pos);                  \
//         }                                                                \
//     } while (0)

// // Add NEW to OLD at position first (assuming first is all we need for now)
// // Can probably drop TYPE with some preprocessor smarts
// #define LISTP_SPLICE(NEW, OLD, FIELD, TYPE)                                      \
//     do {                                                                         \
//         if (!LISTP_EMPTY(NEW)) {                                                 \
//             if (LISTP_EMPTY(OLD)) {                                              \
//                 (OLD)->first = (NEW)->first;                                     \
//             } else {                                                             \
//                 struct TYPE* last_old                = (OLD)->first->FIELD.prev; \
//                 (OLD)->first->FIELD.prev->FIELD.next = (NEW)->first;             \
//                 (OLD)->first->FIELD.prev             = (NEW)->first->FIELD.prev; \
//                 (NEW)->first->FIELD.prev->FIELD.next = (OLD)->first;             \
//                 (NEW)->first->FIELD.prev             = last_old;                 \
//                 (OLD)->first                         = (NEW)->first;             \
//             }                                                                    \
//         }                                                                        \
//     } while (0)

// // Add NEW to OLD at last position
// // Can probably drop TYPE with some preprocessor smarts
// #define LISTP_SPLICE_TAIL(NEW, OLD, FIELD, TYPE)                                 \
//     do {                                                                         \
//         if (!LISTP_EMPTY(NEW)) {                                                 \
//             if (LISTP_EMPTY(OLD)) {                                              \
//                 (OLD)->first = (NEW)->first;                                     \
//             } else {                                                             \
//                 struct TYPE* last_old                = (OLD)->first->FIELD.prev; \
//                 last_old->FIELD.next                 = (NEW)->first;             \
//                 (OLD)->first->FIELD.prev             = (NEW)->first->FIELD.prev; \
//                 (NEW)->first->FIELD.prev->FIELD.next = (OLD)->first;             \
//                 (NEW)->first->FIELD.prev             = last_old;                 \
//             }                                                                    \
//         }                                                                        \
//     } while (0)

// #define LISTP_SPLICE_INIT(NEW, OLD, FIELD, TYPE) \
//     do {                                         \
//         LISTP_SPLICE(NEW, OLD, FIELD, TYPE);     \
//         INIT_LISTP(NEW);                         \
//     } while (0);

// #define LISTP_SPLICE_TAIL_INIT(NEW, OLD, FIELD, TYPE) \
//     do {                                              \
//         LISTP_SPLICE_TAIL(NEW, OLD, FIELD, TYPE);     \
//         INIT_LISTP(NEW);                              \
//     } while (0);

// // list_move_tail - delete from OLD, make tail of NEW
// #define LISTP_MOVE_TAIL(NODE, NEW, OLD, FIELD) \
//     do {                                       \
//         LISTP_DEL_INIT(NODE, OLD, FIELD);      \
//         LISTP_ADD_TAIL(NODE, NEW, FIELD);      \
//     } while (0)

#include "g_list.h"

//lru_cache.h
////////////////////////////////////


struct lruc_context;
typedef struct lruc_context lruc_context_t;

lruc_context_t* lruc_create(void);
void lruc_destroy(lruc_context_t* context);
bool lruc_add(lruc_context_t* context, uint64_t key, void* data); // key must not already exist
void* lruc_get(lruc_context_t* context, uint64_t key);
void* lruc_find(lruc_context_t* context,
                uint64_t key); // only returns the object, does not bump it to the head
size_t lruc_size(lruc_context_t* context);
void* lruc_get_first(lruc_context_t* context);
void* lruc_get_next(lruc_context_t* context);
void* lruc_get_last(lruc_context_t* context);
void lruc_remove_last(lruc_context_t* context);

void lruc_test(void);


//protected_files.h
////////////////////////////////////



/*! Size of IV for AES-GCM */
#define PF_IV_SIZE 12

/*! Size of MAC fields */
#define PF_MAC_SIZE 16

typedef uint8_t pf_iv_t[PF_IV_SIZE];
typedef uint8_t pf_mac_t[PF_MAC_SIZE];

typedef uint8_t pf_keyid_t[32]; /* key derivation material */

extern pf_key_t g_pf_wrap_key;
extern bool g_pf_wrap_key_set;



#define PF_SUCCESS(status) ((status) == PF_STATUS_SUCCESS)
#define PF_FAILURE(status) ((status) != PF_STATUS_SUCCESS)

#define PF_NODE_SIZE 4096U



/*!
 * \brief File read callback
 *
 * \param [in] handle File handle
 * \param [out] buffer Buffer to read to
 * \param [in] offset Offset to read from
 * \param [in] size Number of bytes to read
 * \return PF status
 */
typedef pf_status_t (*pf_read_f)(pf_handle_t handle, void* buffer, uint64_t offset, size_t size);

/*!
 * \brief File write callback
 *
 * \param [in] handle File handle
 * \param [in] buffer Buffer to write from
 * \param [in] offset Offset to write to
 * \param [in] size Number of bytes to write
 * \return PF status
 */
typedef pf_status_t (*pf_write_f)(pf_handle_t handle, const void* buffer, uint64_t offset,
                                  size_t size);

/*!
 * \brief File truncate callback
 *
 * \param [in] handle File handle
 * \param [in] size Target file size
 * \return PF status
 */
typedef pf_status_t (*pf_truncate_f)(pf_handle_t handle, uint64_t size);

/*!
 * \brief Debug print callback
 *
 * \param [in] msg Message to print
 */
typedef void (*pf_debug_f)(const char* msg);

/*!
 * \brief AES-GCM encrypt callback
 *
 * \param [in] key AES-GCM key
 * \param [in] iv Initialization vector
 * \param [in] aad (optional) Additional authenticated data
 * \param [in] aad_size Size of \a aad in bytes
 * \param [in] input Plaintext data
 * \param [in] input_size Size of \a input in bytes
 * \param [out] output Buffer for encrypted data (size: \a input_size)
 * \param [out] mac MAC computed for \a input and \a aad
 * \return PF status
 */
typedef pf_status_t (*pf_aes_gcm_encrypt_f)(const pf_key_t* key, const pf_iv_t* iv, const void* aad,
                                            size_t aad_size, const void* input, size_t input_size,
                                            void* output, pf_mac_t* mac);

/*!
 * \brief AES-GCM decrypt callback
 *
 * \param [in] key AES-GCM key
 * \param [in] iv Initialization vector
 * \param [in] aad (optional) Additional authenticated data
 * \param [in] aad_size Size of \a aad in bytes
 * \param [in] input Encrypted data
 * \param [in] input_size Size of \a input in bytes
 * \param [out] output Buffer for decrypted data (size: \a input_size)
 * \param [in] mac Expected MAC
 * \return PF status
 */
typedef pf_status_t (*pf_aes_gcm_decrypt_f)(const pf_key_t* key, const pf_iv_t* iv, const void* aad,
                                            size_t aad_size, const void* input, size_t input_size,
                                            void* output, const pf_mac_t* mac);

/*!
 * \brief Cryptographic random number generator callback
 *
 * \param [out] buffer Buffer to fill with random bytes
 * \param [in] size Size of \a buffer in bytes
 * \return PF status
 */
typedef pf_status_t (*pf_random_f)(uint8_t* buffer, size_t size);

/*!
 * \brief Initialize I/O callbacks
 *
 * \param [in] read_f File read callback
 * \param [in] write_f File write callback
 * \param [in] truncate_f File truncate callback
 * \param [in] aes_gcm_encrypt_f AES-GCM encrypt callback
 * \param [in] aes_gcm_decrypt_f AES-GCM decrypt callback
 * \param [in] random_f Cryptographic random number generator callback
 * \param [in] debug_f (optional) Debug print callback
 *
 * \details Must be called before any actual APIs
 */
void pf_set_callbacks(pf_read_f read_f, pf_write_f write_f, pf_truncate_f truncate_f,
                      pf_aes_gcm_encrypt_f aes_gcm_encrypt_f,
                      pf_aes_gcm_decrypt_f aes_gcm_decrypt_f, pf_random_f random_f,
                      pf_debug_f debug_f);



/* Public API */

/*!
 * \brief Open a protected file
 *
 * \param [in] handle Open underlying file handle
 * \param [in] path Path to the file. If NULL and \a create is false, don't check path for validity.
 * \param [in] underlying_size Underlying file size
 * \param [in] mode Access mode
 * \param [in] create Overwrite file contents if true
 * \param [in] key Wrap key
 * \param [out] context PF context for later calls
 * \return PF status
 */
pf_status_t g_pf_open(pf_handle_t handle, const char* path, uint64_t underlying_size,
                    pf_file_mode_t mode, bool create, const pf_key_t* key, pf_context_t** context);

/*!
 * \brief Close a protected file and commit all changes to disk
 *
 * \param [in] pf PF context
 * \return PF status
 */
pf_status_t pf_close(pf_context_t* pf);

/*!
 * \brief Read from a protected file
 *
 * \param [in] pf PF context
 * \param [in] offset Data offset to read from
 * \param [in] size Number of bytes to read
 * \param [out] output Destination buffer
 * \param [out] bytes_read Number of bytes actually read
 * \return PF status
 */
pf_status_t pf_read(pf_context_t* pf, uint64_t offset, size_t size, void* output,
                    size_t* bytes_read);

/*!
 * \brief Write to a protected file
 *
 * \param [in] pf PF context
 * \param [in] offset Data offset to write to
 * \param [in] size Number of bytes to write
 * \param [in] input Source buffer
 * \return PF status
 */
pf_status_t pf_write(pf_context_t* pf, uint64_t offset, size_t size, const void* input);

/*!
 * \brief Get data size of a PF
 *
 * \param [in] pf PF context
 * \param [out] size Data size of \a pf
 * \return PF status
 */
pf_status_t pf_get_size(pf_context_t* pf, uint64_t* size);

/*!
 * \brief Set data size of a PF
 *
 * \param [in] pf PF context
 * \param [in] size Data size to set
 * \return PF status
 * \details If the file is extended, added bytes are zero.
 *          Truncation is not implemented yet (TODO).
 */
pf_status_t pf_set_size(pf_context_t* pf, uint64_t size);

/*!
 * \brief Get underlying handle of a PF
 *
 * \param [in] pf PF context
 * \param [out] handle Handle to the backing file
 * \return PF status
 */
pf_status_t pf_get_handle(pf_context_t* pf, pf_handle_t* handle);

/*!
 * \brief Flush any pending data of a protected file to disk
 *
 * \param [in] pf PF context
 * \return PF status
 */
pf_status_t pf_flush(pf_context_t* pf);



//protected_files_format.h
////////////////////////////////////

#define PF_FILE_ID       0x46505f4850415247 /* GRAPH_PF */
#define PF_MAJOR_VERSION 0x01
#define PF_MINOR_VERSION 0x00

#define METADATA_KEY_NAME "SGX-PROTECTED-FS-METADATA-KEY"
#define MAX_LABEL_SIZE    64

static_assert(sizeof(METADATA_KEY_NAME) <= MAX_LABEL_SIZE, "label too long");

#pragma pack(push, 1)

typedef struct _metadata_plain {
    uint64_t   file_id;
    uint8_t    major_version;
    uint8_t    minor_version;
    pf_keyid_t metadata_key_id;
    pf_mac_t   metadata_gmac; /* GCM mac */
} metadata_plain_t;

#define PATH_MAX_SIZE (260 + 512)

// these are all defined as relative to node size, so we can decrease node size in tests
// and have deeper tree
#define MD_USER_DATA_SIZE (PF_NODE_SIZE * 3 / 4) // 3072
static_assert(MD_USER_DATA_SIZE == 3072, "bad struct size");

typedef struct _metadata_encrypted {
    char     path[PATH_MAX_SIZE];
    uint64_t size;
    pf_key_t mht_key;
    pf_mac_t mht_gmac;
    uint8_t  data[MD_USER_DATA_SIZE];
} metadata_encrypted_t;

typedef uint8_t metadata_encrypted_blob_t[sizeof(metadata_encrypted_t)];

#define METADATA_NODE_SIZE PF_NODE_SIZE

typedef uint8_t metadata_padding_t[METADATA_NODE_SIZE -
                                   (sizeof(metadata_plain_t) + sizeof(metadata_encrypted_blob_t))];

typedef struct _metadata_node {
    metadata_plain_t          plain_part;
    metadata_encrypted_blob_t encrypted_part;
    metadata_padding_t        padding;
} metadata_node_t;

static_assert(sizeof(metadata_node_t) == PF_NODE_SIZE, "sizeof(metadata_node_t)");

typedef struct _data_node_crypto {
    pf_key_t key;
    pf_mac_t gmac;
} gcm_crypto_data_t;

// for PF_NODE_SIZE == 4096, we have 96 attached data nodes and 32 mht child nodes
// for PF_NODE_SIZE == 2048, we have 48 attached data nodes and 16 mht child nodes
// for PF_NODE_SIZE == 1024, we have 24 attached data nodes and 8 mht child nodes
// 3/4 of the node size is dedicated to data nodes
#define ATTACHED_DATA_NODES_COUNT ((PF_NODE_SIZE / sizeof(gcm_crypto_data_t)) * 3 / 4)
static_assert(ATTACHED_DATA_NODES_COUNT == 96, "ATTACHED_DATA_NODES_COUNT");
// 1/4 of the node size is dedicated to child mht nodes
#define CHILD_MHT_NODES_COUNT ((PF_NODE_SIZE / sizeof(gcm_crypto_data_t)) * 1 / 4)
static_assert(CHILD_MHT_NODES_COUNT == 32, "CHILD_MHT_NODES_COUNT");

typedef struct _mht_node {
    gcm_crypto_data_t data_nodes_crypto[ATTACHED_DATA_NODES_COUNT];
    gcm_crypto_data_t mht_nodes_crypto[CHILD_MHT_NODES_COUNT];
} mht_node_t;

static_assert(sizeof(mht_node_t) == PF_NODE_SIZE, "sizeof(mht_node_t)");

typedef struct _data_node {
    uint8_t data[PF_NODE_SIZE];
} data_node_t;

static_assert(sizeof(data_node_t) == PF_NODE_SIZE, "sizeof(data_node_t)");

typedef struct _encrypted_node {
    uint8_t cipher[PF_NODE_SIZE];
} encrypted_node_t;

static_assert(sizeof(encrypted_node_t) == PF_NODE_SIZE, "sizeof(encrypted_node_t)");

#define MAX_PAGES_IN_CACHE 48

typedef enum {
    FILE_MHT_NODE_TYPE  = 1,
    FILE_DATA_NODE_TYPE = 2,
} mht_node_type_e;

// make sure these are the same size
static_assert(sizeof(mht_node_t) == sizeof(data_node_t),
              "sizeof(mht_node_t) == sizeof(data_node_t)");

DEFINE_LIST(_file_node);
typedef struct _file_node {
    LIST_TYPE(_file_node) list;
    uint8_t type;
    uint64_t node_number;
    struct _file_node* parent;
    bool need_writing;
    bool new_node;
    struct {
        uint64_t physical_node_number;
        encrypted_node_t encrypted; // the actual data from the disk
    };
    union { // decrypted data
        mht_node_t mht;
        data_node_t data;
    } decrypted;
} file_node_t;
DEFINE_LISTP(_file_node);

typedef struct {
    uint32_t index;
    char label[MAX_LABEL_SIZE]; // must be NULL terminated
    pf_keyid_t nonce;
    uint32_t output_len; // in bits
} kdf_input_t;

#pragma pack(pop)



//protected_files_internal.h
////////////////////////////////////

struct pf_context {
    metadata_node_t file_metadata; // actual data from disk's meta data node
    pf_status_t last_error;
    metadata_encrypted_t encrypted_part_plain; // encrypted part of metadata node, decrypted
    file_node_t root_mht; // the root of the mht is always needed (for files bigger than 3KB)
    pf_handle_t file;
    pf_file_mode_t mode;
    uint64_t offset; // current file position (user's view)
    bool end_of_file;
    uint64_t real_file_size;
    bool need_writing;
    pf_status_t file_status;
    pf_key_t user_kdk_key;
    pf_key_t cur_key;
    lruc_context_t* cache;
#ifdef DEBUG
    char* debug_buffer; // buffer for debug output
#endif
};

/* ipf prefix means "Intel protected files", these are functions from the SGX SDK implementation */
static bool ipf_init_fields(pf_context_t* pf);
static bool ipf_init_existing_file(pf_context_t* pf, const char* path);
static bool ipf_init_new_file(pf_context_t* pf, const char* path);

static bool ipf_read_node(pf_context_t* pf, pf_handle_t handle, uint64_t node_number, void* buffer,
                          uint32_t node_size);
static bool ipf_write_node(pf_context_t* pf, pf_handle_t handle, uint64_t node_number, void* buffer,
                           uint32_t node_size);

static bool ipf_import_metadata_key(pf_context_t* pf, bool restore, pf_key_t* output);
static bool ipf_generate_random_key(pf_context_t* pf, pf_key_t* output);
static bool ipf_restore_current_metadata_key(pf_context_t* pf, pf_key_t* output);

static file_node_t* ipf_get_data_node(pf_context_t* pf);
static file_node_t* ipf_read_data_node(pf_context_t* pf);
static file_node_t* ipf_append_data_node(pf_context_t* pf);
static file_node_t* ipf_get_mht_node(pf_context_t* pf);
static file_node_t* ipf_read_mht_node(pf_context_t* pf, uint64_t mht_node_number);
static file_node_t* ipf_append_mht_node(pf_context_t* pf, uint64_t mht_node_number);

static bool ipf_update_all_data_and_mht_nodes(pf_context_t* pf);
static bool ipf_update_metadata_node(pf_context_t* pf);
static bool ipf_write_all_changes_to_disk(pf_context_t* pf);
static bool ipf_internal_flush(pf_context_t* pf);

static pf_context_t* ipf_open(const char* path, pf_file_mode_t mode, bool create, pf_handle_t file,
                              size_t real_size, const pf_key_t* kdk_key, pf_status_t* status);
static bool ipf_close(pf_context_t* pf);
static size_t ipf_read(pf_context_t* pf, void* ptr, size_t size);
static size_t ipf_write(pf_context_t* pf, const void* ptr, size_t size);
static bool ipf_seek(pf_context_t* pf, uint64_t new_offset);
static void ipf_try_clear_error(pf_context_t* pf);




#endif /* PROTECTED_FILES_H_ */