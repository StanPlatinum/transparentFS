#include <limits.h>

#include "assert.h"
#include "g_list.h"
#include "g_lru_cache.h"
#include "g_protected_files.h"
#include "g_protected_files_format.h"

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