/*
    Copyright (C) HWPORT.COM
    All rights reserved.
    Author: JAEHYUK CHO <mailto:minzkn@minzkn.com>
*/

#if !defined(__def_hwport_pgl_header_hwport_aria_h__)
# define __def_hwport_pgl_header_hwport_aria_h__ "hwport_aria.h"

#include <sys/types.h>

#if defined(__cplusplus)
# define def_hwport_aria_import_c extern "C"
#else
# define def_hwport_aria_import_c extern
#endif

#if !defined(hwport_make_round_key_handler_t)
typedef void * (*__hwport_make_round_key_handler_t)(void *s_round_key, const void *s_user_key);
# define hwport_make_round_key_handler_t __hwport_make_round_key_handler_t
#endif

#if !defined(hwport_encrypt_handler_t)
typedef void * (*__hwport_encrypt_handler_t)(void *s_data, size_t s_size, const void *s_round_key);
# define hwport_encrypt_handler_t __hwport_encrypt_handler_t
#endif

#if !defined(hwport_decrypt_handler_t)
typedef void * (*__hwport_decrypt_handler_t)(void *s_data, size_t s_size, const void *s_round_key);
# define hwport_decrypt_handler_t __hwport_decrypt_handler_t
#endif

#define def_hwport_aria_block_size 16

/*
  round key format

  round_key = encrypt_round_key[def_hwport_aria128_encrypt_round_key_size] + decrypt_round_key[def_hwport_aria128_decrypt_round_key_size]
*/

#define def_hwport_aria128_block_size def_hwport_aria_block_size
#define def_hwport_aria128_rounds 12
#define def_hwport_aria128_user_key_size (128/8)
#define def_hwport_aria128_round_keys (def_hwport_aria128_rounds+1)
#define def_hwport_aria128_encrypt_round_key_size (def_hwport_aria128_round_keys*def_hwport_aria128_block_size)
#define def_hwport_aria128_decrypt_round_key_size (def_hwport_aria128_round_keys*def_hwport_aria128_block_size)
#define def_hwport_aria128_encrypt_round_key_offset 0
#define def_hwport_aria128_decrypt_round_key_offset def_hwport_aria128_encrypt_round_key_size
#define def_hwport_aria128_round_key_size ((def_hwport_aria128_round_keys*def_hwport_aria128_block_size)*2)

#define def_hwport_aria192_block_size def_hwport_aria_block_size
#define def_hwport_aria192_rounds 14
#define def_hwport_aria192_user_key_size (192/8)
#define def_hwport_aria192_round_keys (def_hwport_aria192_rounds+1)
#define def_hwport_aria192_encrypt_round_key_size (def_hwport_aria192_round_keys*def_hwport_aria192_block_size)
#define def_hwport_aria192_decrypt_round_key_size (def_hwport_aria192_round_keys*def_hwport_aria192_block_size)
#define def_hwport_aria192_encrypt_round_key_offset 0
#define def_hwport_aria192_decrypt_round_key_offset def_hwport_aria192_encrypt_round_key_size
#define def_hwport_aria192_round_key_size ((def_hwport_aria192_round_keys*def_hwport_aria192_block_size)*2)

#define def_hwport_aria256_block_size def_hwport_aria_block_size
#define def_hwport_aria256_rounds 16
#define def_hwport_aria256_user_key_size (256/8)
#define def_hwport_aria256_round_keys (def_hwport_aria256_rounds+1)
#define def_hwport_aria256_encrypt_round_key_size (def_hwport_aria256_round_keys*def_hwport_aria256_block_size)
#define def_hwport_aria256_decrypt_round_key_size (def_hwport_aria256_round_keys*def_hwport_aria256_block_size)
#define def_hwport_aria256_encrypt_round_key_offset 0
#define def_hwport_aria256_decrypt_round_key_offset def_hwport_aria256_encrypt_round_key_size
#define def_hwport_aria256_round_key_size ((def_hwport_aria256_round_keys*def_hwport_aria256_block_size)*2)

#define def_hwport_aes_max_user_key_size def_hwport_aria256_user_key_size
#define def_hwport_aes_max_round_key_size def_hwport_aria256_round_key_size

#if !defined(__def_hwport_pgl_source_aria_c__)
def_hwport_aria_import_c void *hwport_make_round_key_aria128(void *s_round_key, const void *s_user_key);
def_hwport_aria_import_c void *hwport_encrypt_aria128_ecb(void *s_data, size_t s_size, const void *s_round_key);
def_hwport_aria_import_c void *hwport_decrypt_aria128_ecb(void *s_data, size_t s_size, const void *s_round_key);

def_hwport_aria_import_c void *hwport_make_round_key_aria192(void *s_round_key, const void *s_user_key);
def_hwport_aria_import_c void *hwport_encrypt_aria192_ecb(void *s_data, size_t s_size, const void *s_round_key);
def_hwport_aria_import_c void *hwport_decrypt_aria192_ecb(void *s_data, size_t s_size, const void *s_round_key);

def_hwport_aria_import_c void *hwport_make_round_key_aria256(void *s_round_key, const void *s_user_key);
def_hwport_aria_import_c void *hwport_encrypt_aria256_ecb(void *s_data, size_t s_size, const void *s_round_key);
def_hwport_aria_import_c void *hwport_decrypt_aria256_ecb(void *s_data, size_t s_size, const void *s_round_key);
#endif
#endif

/* vim: set expandtab: */
/* End of source */
