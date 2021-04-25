## APIs

Now we provide 4 ecalls for opening/reading/writing/closing a protected file.

Function signatures can be found in the EDL file.

```
        public pf_status_t g_pf_open(pf_handle_t handle, [in, size=256] const char* path, uint64_t underlying_size,
                    pf_file_mode_t mode, bool create, [in, size=16] const pf_key_t* key, [out] pf_context_t** context);
        public pf_status_t g_pf_read([user_check] pf_context_t* pf, uint64_t offset, [out, size=100] void* output, size_t read_size,
                    [user_check] size_t* bytes_read);
        public pf_status_t g_pf_write([user_check] pf_context_t* pf, uint64_t offset, [in, size=100] const void* input, size_t write_size);
        public pf_status_t g_pf_close([user_check] pf_context_t* pf);
```

A demo can be found at `App/App.cpp`.

Currently, a parameter `pf_key_t* key` is used for transferring the key to encrypt/decrypt the protected file, which is insecure.
We will design a secure transferring scheme next. A global variable at `Enclave/Enclave.cpp` has been set to store the protected key.

Later on we will write other ocalls for an enclave to open/close a protected file. (We have read/write/... ocalls already.)
