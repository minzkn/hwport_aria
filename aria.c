/*
    Copyright (C) HWPORT.COM
    All rights reserved.
    Author: JAEHYUK CHO <mailto:minzkn@minzkn.com>
*/

/*
    https://tools.ietf.org/html/rfc5794 - A Description of the ARIA Encryption Algorithm
*/

#if !defined(__def_hwport_pgl_source_aria_c__)
# define __def_hwport_pgl_source_aria_c__ "aria.c"

/* ---- */

#include <sys/types.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <memory.h>
#include <stdio.h>

#include <arpa/inet.h> /* for htonl(), ntohl() */

#include "hwport_aria.h"

/* ---- */

#define hwport_aria_not_supported() (void)fprintf(stderr, "not supported !\n");

/* ---- */

static void __hwport_make_round_key_aria(void *s_round_key, const void *s_user_key, size_t s_user_key_size);
static void __hwport_do_aria_private(int s_rounds, void *s_data, const void *s_round_key);
static void *__hwport_do_aria_ecb_private(int s_rounds, size_t s_block_size, void *s_data, size_t s_size, const void *s_round_key);

void *hwport_make_round_key_aria128(void *s_round_key, const void *s_user_key);
void *hwport_encrypt_aria128_ecb(void *s_data, size_t s_size, const void *s_round_key);
void *hwport_decrypt_aria128_ecb(void *s_data, size_t s_size, const void *s_round_key);

void *hwport_make_round_key_aria192(void *s_round_key, const void *s_user_key);
void *hwport_encrypt_aria192_ecb(void *s_data, size_t s_size, const void *s_round_key);
void *hwport_decrypt_aria192_ecb(void *s_data, size_t s_size, const void *s_round_key);

void *hwport_make_round_key_aria256(void *s_round_key, const void *s_user_key);
void *hwport_encrypt_aria256_ecb(void *s_data, size_t s_size, const void *s_round_key);
void *hwport_decrypt_aria256_ecb(void *s_data, size_t s_size, const void *s_round_key);

static const uint8_t __gc_hwport_aria_s_box[ /* 4u */ ][ 256u ] = {
    { /* [SB1] Table1: S-box S1 */
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    },
    { /* [SB2] Table3: S-box S2 */
        0xE2, 0x4E, 0x54, 0xFC, 0x94, 0xC2, 0x4A, 0xCC, 0x62, 0x0D, 0x6A, 0x46, 0x3C, 0x4D, 0x8B, 0xD1,
        0x5E, 0xFA, 0x64, 0xCB, 0xB4, 0x97, 0xBE, 0x2B, 0xBC, 0x77, 0x2E, 0x03, 0xD3, 0x19, 0x59, 0xC1,
        0x1D, 0x06, 0x41, 0x6B, 0x55, 0xF0, 0x99, 0x69, 0xEA, 0x9C, 0x18, 0xAE, 0x63, 0xDF, 0xE7, 0xBB,
        0x00, 0x73, 0x66, 0xFB, 0x96, 0x4C, 0x85, 0xE4, 0x3A, 0x09, 0x45, 0xAA, 0x0F, 0xEE, 0x10, 0xEB,
        0x2D, 0x7F, 0xF4, 0x29, 0xAC, 0xCF, 0xAD, 0x91, 0x8D, 0x78, 0xC8, 0x95, 0xF9, 0x2F, 0xCE, 0xCD,
        0x08, 0x7A, 0x88, 0x38, 0x5C, 0x83, 0x2A, 0x28, 0x47, 0xDB, 0xB8, 0xC7, 0x93, 0xA4, 0x12, 0x53,
        0xFF, 0x87, 0x0E, 0x31, 0x36, 0x21, 0x58, 0x48, 0x01, 0x8E, 0x37, 0x74, 0x32, 0xCA, 0xE9, 0xB1,
        0xB7, 0xAB, 0x0C, 0xD7, 0xC4, 0x56, 0x42, 0x26, 0x07, 0x98, 0x60, 0xD9, 0xB6, 0xB9, 0x11, 0x40,
        0xEC, 0x20, 0x8C, 0xBD, 0xA0, 0xC9, 0x84, 0x04, 0x49, 0x23, 0xF1, 0x4F, 0x50, 0x1F, 0x13, 0xDC,
        0xD8, 0xC0, 0x9E, 0x57, 0xE3, 0xC3, 0x7B, 0x65, 0x3B, 0x02, 0x8F, 0x3E, 0xE8, 0x25, 0x92, 0xE5,
        0x15, 0xDD, 0xFD, 0x17, 0xA9, 0xBF, 0xD4, 0x9A, 0x7E, 0xC5, 0x39, 0x67, 0xFE, 0x76, 0x9D, 0x43,
        0xA7, 0xE1, 0xD0, 0xF5, 0x68, 0xF2, 0x1B, 0x34, 0x70, 0x05, 0xA3, 0x8A, 0xD5, 0x79, 0x86, 0xA8,
        0x30, 0xC6, 0x51, 0x4B, 0x1E, 0xA6, 0x27, 0xF6, 0x35, 0xD2, 0x6E, 0x24, 0x16, 0x82, 0x5F, 0xDA,
        0xE6, 0x75, 0xA2, 0xEF, 0x2C, 0xB2, 0x1C, 0x9F, 0x5D, 0x6F, 0x80, 0x0A, 0x72, 0x44, 0x9B, 0x6C,
        0x90, 0x0B, 0x5B, 0x33, 0x7D, 0x5A, 0x52, 0xF3, 0x61, 0xA1, 0xF7, 0xB0, 0xD6, 0x3F, 0x7C, 0x6D,
        0xED, 0x14, 0xE0, 0xA5, 0x3D, 0x22, 0xB3, 0xF8, 0x89, 0xDE, 0x71, 0x1A, 0xAF, 0xBA, 0xB5, 0x81
    },
    { /* [SB3] Table2: S-box S1 inverse (S1-1) */
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
    },
    { /* [SB4] Table4: S-box S2 inverse (S2-1) */
        0x30, 0x68, 0x99, 0x1B, 0x87, 0xB9, 0x21, 0x78, 0x50, 0x39, 0xDB, 0xE1, 0x72, 0x09, 0x62, 0x3C,
        0x3E, 0x7E, 0x5E, 0x8E, 0xF1, 0xA0, 0xCC, 0xA3, 0x2A, 0x1D, 0xFB, 0xB6, 0xD6, 0x20, 0xC4, 0x8D,
        0x81, 0x65, 0xF5, 0x89, 0xCB, 0x9D, 0x77, 0xC6, 0x57, 0x43, 0x56, 0x17, 0xD4, 0x40, 0x1A, 0x4D,
        0xC0, 0x63, 0x6C, 0xE3, 0xB7, 0xC8, 0x64, 0x6A, 0x53, 0xAA, 0x38, 0x98, 0x0C, 0xF4, 0x9B, 0xED,
        0x7F, 0x22, 0x76, 0xAF, 0xDD, 0x3A, 0x0B, 0x58, 0x67, 0x88, 0x06, 0xC3, 0x35, 0x0D, 0x01, 0x8B,
        0x8C, 0xC2, 0xE6, 0x5F, 0x02, 0x24, 0x75, 0x93, 0x66, 0x1E, 0xE5, 0xE2, 0x54, 0xD8, 0x10, 0xCE,
        0x7A, 0xE8, 0x08, 0x2C, 0x12, 0x97, 0x32, 0xAB, 0xB4, 0x27, 0x0A, 0x23, 0xDF, 0xEF, 0xCA, 0xD9,
        0xB8, 0xFA, 0xDC, 0x31, 0x6B, 0xD1, 0xAD, 0x19, 0x49, 0xBD, 0x51, 0x96, 0xEE, 0xE4, 0xA8, 0x41,
        0xDA, 0xFF, 0xCD, 0x55, 0x86, 0x36, 0xBE, 0x61, 0x52, 0xF8, 0xBB, 0x0E, 0x82, 0x48, 0x69, 0x9A,
        0xE0, 0x47, 0x9E, 0x5C, 0x04, 0x4B, 0x34, 0x15, 0x79, 0x26, 0xA7, 0xDE, 0x29, 0xAE, 0x92, 0xD7,
        0x84, 0xE9, 0xD2, 0xBA, 0x5D, 0xF3, 0xC5, 0xB0, 0xBF, 0xA4, 0x3B, 0x71, 0x44, 0x46, 0x2B, 0xFC,
        0xEB, 0x6F, 0xD5, 0xF6, 0x14, 0xFE, 0x7C, 0x70, 0x5A, 0x7D, 0xFD, 0x2F, 0x18, 0x83, 0x16, 0xA5,
        0x91, 0x1F, 0x05, 0x95, 0x74, 0xA9, 0xC1, 0x5B, 0x4A, 0x85, 0x6D, 0x13, 0x07, 0x4F, 0x4E, 0x45,
        0xB2, 0x0F, 0xC9, 0x1C, 0xA6, 0xBC, 0xEC, 0x73, 0x90, 0x7B, 0xCF, 0x59, 0x8F, 0xA1, 0xF9, 0x2D,
        0xF2, 0xB1, 0x00, 0x94, 0x37, 0x9F, 0xD0, 0x2E, 0x9C, 0x6E, 0x28, 0x3F, 0x80, 0xF0, 0x3D, 0xD3,
        0x25, 0x8A, 0xB5, 0xE7, 0x42, 0xB3, 0xC7, 0xEA, 0xF7, 0x4C, 0x11, 0x33, 0x03, 0xA2, 0xAC, 0x60
    }
};

/*
    key scheduling constants 
      C1 =  0x517cc1b727220a94fe13abe8fa9a6ee0
      C2 =  0x6db14acc9e21c820ff28b1d5ef5de2b0
      C3 =  0xdb92371d2126e9700324977504e8c90e
*/
static const uint32_t __gc_hwport_aria_ksc_he32[ /* 12 */ ] = {
   /* C1 */ 0x517CC1B7, 0x27220A94, 0xFE13ABE8, 0xFA9A6EE0,
   /* C2 */ 0x6DB14ACC, 0x9E21C820, 0xFF28B1D5, 0xEF5DE2B0,
   /* C3 */ 0xDB92371D, 0x2126E970, 0x03249775, 0x04E8C90E
};

/* ---- */

/* move operation : (uint32_t *m_to, const uint32_t *m_from) */
#define __hwport_aria_mov128(m_to,m_from) do { \
    (m_to)[0u]=(m_from)[0u]; \
    (m_to)[1u]=(m_from)[1u]; \
    (m_to)[2u]=(m_from)[2u]; \
    (m_to)[3u]=(m_from)[3u]; \
}while(0)

/* xor operation : (uint32_t *m_to, const uint32_t *m_from) */
#define __hwport_aria_xor128(m_to,m_from) do { \
    (m_to)[0u]^=(m_from)[0u]; \
    (m_to)[1u]^=(m_from)[1u]; \
    (m_to)[2u]^=(m_from)[2u]; \
    (m_to)[3u]^=(m_from)[3u]; \
}while(0)

/* rotate left operation : (uint32_t *m_to, uint32_t *m_from, const unsigned int) */
#define __hwport_aria_rol128(m_to,m_from,m_bits) do { \
    (m_to)[0u]=((m_from)[(((m_bits)>>5)+0u)&3u]<<((m_bits)&31u))|((m_from)[(((m_bits)>>5)+1u)&3u]>>(32u-((m_bits)&31u))); \
    (m_to)[1u]=((m_from)[(((m_bits)>>5)+1u)&3u]<<((m_bits)&31u))|((m_from)[(((m_bits)>>5)+2u)&3u]>>(32u-((m_bits)&31u))); \
    (m_to)[2u]=((m_from)[(((m_bits)>>5)+2u)&3u]<<((m_bits)&31u))|((m_from)[(((m_bits)>>5)+3u)&3u]>>(32u-((m_bits)&31u))); \
    (m_to)[3u]=((m_from)[(((m_bits)>>5)+3u)&3u]<<((m_bits)&31u))|((m_from)[(((m_bits)>>5)+0u)&3u]>>(32u-((m_bits)&31u))); \
}while(0)

/*
    ARIA substitution layer, type1 operation : (uint32_t *m_to, const uint32_t *m_from)

    S1, S2, S1-1, S2-1, S1, S2, S1-1, S2-1, S1, S2, S1-1, S2-1, S1, S2, S1-1, S2-1, 
*/
#define __hwport_aria_substitution_layer_type1(m_to,m_from) do { \
    const uint8_t *_m_x=(const uint8_t *)(m_from); \
    uint8_t *_m_y=(uint8_t *)(m_to); \
    _m_y[0u]=__gc_hwport_aria_s_box[0 /* SB1 */][_m_x[0u]]; \
    _m_y[1u]=__gc_hwport_aria_s_box[1 /* SB2 */][_m_x[1u]]; \
    _m_y[2u]=__gc_hwport_aria_s_box[2 /* SB3 */][_m_x[2u]]; \
    _m_y[3u]=__gc_hwport_aria_s_box[3 /* SB4 */][_m_x[3u]]; \
    _m_y[4u]=__gc_hwport_aria_s_box[0 /* SB1 */][_m_x[4u]]; \
    _m_y[5u]=__gc_hwport_aria_s_box[1 /* SB2 */][_m_x[5u]]; \
    _m_y[6u]=__gc_hwport_aria_s_box[2 /* SB3 */][_m_x[6u]]; \
    _m_y[7u]=__gc_hwport_aria_s_box[3 /* SB4 */][_m_x[7u]]; \
    _m_y[8u]=__gc_hwport_aria_s_box[0 /* SB1 */][_m_x[8u]]; \
    _m_y[9u]=__gc_hwport_aria_s_box[1 /* SB2 */][_m_x[9u]]; \
    _m_y[10u]=__gc_hwport_aria_s_box[2 /* SB3 */][_m_x[10u]]; \
    _m_y[11u]=__gc_hwport_aria_s_box[3 /* SB4 */][_m_x[11u]]; \
    _m_y[12u]=__gc_hwport_aria_s_box[0 /* SB1 */][_m_x[12u]]; \
    _m_y[13u]=__gc_hwport_aria_s_box[1 /* SB2 */][_m_x[13u]]; \
    _m_y[14u]=__gc_hwport_aria_s_box[2 /* SB3 */][_m_x[14u]]; \
    _m_y[15u]=__gc_hwport_aria_s_box[3 /* SB4 */][_m_x[15u]]; \
}while(0)

/*
    ARIA substitution layer, type2 operation : (uint32_t *m_to, const uint32_t *m_from)

    S1-1, S2-1, S1, S2, S1-1, S2-1, S1, S2, S1-1, S2-1, S1, S2, S1-1, S2-1, S1, S2 
*/
#define __hwport_aria_substitution_layer_type2(m_to,m_from) do { \
    const uint8_t *_mx=(const uint8_t *)(m_from); \
    uint8_t *_m_y=(uint8_t *)(m_to); \
    _m_y[0u]=__gc_hwport_aria_s_box[2 /* SB3 */][_mx[0u]]; \
    _m_y[1u]=__gc_hwport_aria_s_box[3 /* SB4 */][_mx[1u]]; \
    _m_y[2u]=__gc_hwport_aria_s_box[0 /* SB1 */][_mx[2u]]; \
    _m_y[3u]=__gc_hwport_aria_s_box[1 /* SB2 */][_mx[3u]]; \
    _m_y[4u]=__gc_hwport_aria_s_box[2 /* SB3 */][_mx[4u]]; \
    _m_y[5u]=__gc_hwport_aria_s_box[3 /* SB4 */][_mx[5u]]; \
    _m_y[6u]=__gc_hwport_aria_s_box[0 /* SB1 */][_mx[6u]]; \
    _m_y[7u]=__gc_hwport_aria_s_box[1 /* SB2 */][_mx[7u]]; \
    _m_y[8u]=__gc_hwport_aria_s_box[2 /* SB3 */][_mx[8u]]; \
    _m_y[9u]=__gc_hwport_aria_s_box[3 /* SB4 */][_mx[9u]]; \
    _m_y[10u]=__gc_hwport_aria_s_box[0 /* SB1 */][_mx[10u]]; \
    _m_y[11u]=__gc_hwport_aria_s_box[1 /* SB2 */][_mx[11u]]; \
    _m_y[12u]=__gc_hwport_aria_s_box[2 /* SB3 */][_mx[12u]]; \
    _m_y[13u]=__gc_hwport_aria_s_box[3 /* SB4 */][_mx[13u]]; \
    _m_y[14u]=__gc_hwport_aria_s_box[0 /* SB1 */][_mx[14u]]; \
    _m_y[15u]=__gc_hwport_aria_s_box[1 /* SB2 */][_mx[15u]]; \
}while(0)

/*
    diffusion layer A operatioin : (void *m_to, const void *m_from)

    The diffusion layer A of ARIA is a function which maps an input (x0, x1, ..., x15) of 16 bytes into an output (y0, y1, ..., y15). 
      y0  = x3 ^ x4 ^ x6 ^ x8  ^ x9  ^ x13 ^ x14,
      y1  = x2 ^ x5 ^ x7 ^ x8  ^ x9  ^ x12 ^ x15,
      y2  = x1 ^ x4 ^ x6 ^ x10 ^ x11 ^ x12 ^ x15,
      y3  = x0 ^ x5 ^ x7 ^ x10 ^ x11 ^ x13 ^ x14,
      y4  = x0 ^ x2 ^ x5 ^ x8  ^ x11 ^ x14 ^ x15,
      y5  = x1 ^ x3 ^ x4 ^ x9  ^ x10 ^ x14 ^ x15,
      y6  = x0 ^ x2 ^ x7 ^ x9  ^ x10 ^ x12 ^ x13,
      y7  = x1 ^ x3 ^ x6 ^ x8  ^ x11 ^ x12 ^ x13,
      y8  = x0 ^ x1 ^ x4 ^ x7  ^ x10 ^ x13 ^ x15,
      y9  = x0 ^ x1 ^ x5 ^ x6  ^ x11 ^ x12 ^ x14,
      y10 = x2 ^ x3 ^ x5 ^ x6  ^ x8  ^ x13 ^ x15,
      y11 = x2 ^ x3 ^ x4 ^ x7  ^ x9  ^ x12 ^ x14,
      y12 = x1 ^ x2 ^ x6 ^ x7  ^ x9  ^ x11 ^ x12,
      y13 = x0 ^ x3 ^ x6 ^ x7  ^ x8  ^ x10 ^ x13,
      y14 = x0 ^ x3 ^ x4 ^ x5  ^ x9  ^ x11 ^ x14,
      y15 = x1 ^ x2 ^ x4 ^ x5  ^ x8  ^ x10 ^ x15.
*/
#define __hwport_aria_diffusion_layer_A(m_to,m_from) do { \
    const uint8_t *_m_x=(const uint8_t *)(m_from); \
    uint8_t *_m_y=(uint8_t *)(m_to); \
    _m_y[0u]=_m_x[3u]^_m_x[4u]^_m_x[6u]^_m_x[8u]^_m_x[9u]^_m_x[13u]^_m_x[14u]; \
    _m_y[1u]=_m_x[2u]^_m_x[5u]^_m_x[7u]^_m_x[8u]^_m_x[9u]^_m_x[12u]^_m_x[15u]; \
    _m_y[2u]=_m_x[1u]^_m_x[4u]^_m_x[6u]^_m_x[10u]^_m_x[11u]^_m_x[12u]^_m_x[15u]; \
    _m_y[3u]=_m_x[0u]^_m_x[5u]^_m_x[7u]^_m_x[10u]^_m_x[11u]^_m_x[13u]^_m_x[14u]; \
    _m_y[4u]=_m_x[0u]^_m_x[2u]^_m_x[5u]^_m_x[8u]^_m_x[11u]^_m_x[14u]^_m_x[15u]; \
    _m_y[5u]=_m_x[1u]^_m_x[3u]^_m_x[4u]^_m_x[9u]^_m_x[10u]^_m_x[14u]^_m_x[15u]; \
    _m_y[6u]=_m_x[0u]^_m_x[2u]^_m_x[7u]^_m_x[9u]^_m_x[10u]^_m_x[12u]^_m_x[13u]; \
    _m_y[7u]=_m_x[1u]^_m_x[3u]^_m_x[6u]^_m_x[8u]^_m_x[11u]^_m_x[12u]^_m_x[13u]; \
    _m_y[8u]=_m_x[0u]^_m_x[1u]^_m_x[4u]^_m_x[7u]^_m_x[10u]^_m_x[13u]^_m_x[15u]; \
    _m_y[9u]=_m_x[0u]^_m_x[1u]^_m_x[5u]^_m_x[6u]^_m_x[11u]^_m_x[12u]^_m_x[14u]; \
    _m_y[10u]=_m_x[2u]^_m_x[3u]^_m_x[5u]^_m_x[6u]^_m_x[8u]^_m_x[13u]^_m_x[15u]; \
    _m_y[11u]=_m_x[2u]^_m_x[3u]^_m_x[4u]^_m_x[7u]^_m_x[9u]^_m_x[12u]^_m_x[14u]; \
    _m_y[12u]=_m_x[1u]^_m_x[2u]^_m_x[6u]^_m_x[7u]^_m_x[9u]^_m_x[11u]^_m_x[12u]; \
    _m_y[13u]=_m_x[0u]^_m_x[3u]^_m_x[6u]^_m_x[7u]^_m_x[8u]^_m_x[10u]^_m_x[13u]; \
    _m_y[14u]=_m_x[0u]^_m_x[3u]^_m_x[4u]^_m_x[5u]^_m_x[9u]^_m_x[11u]^_m_x[14u]; \
    _m_y[15u]=_m_x[1u]^_m_x[2u]^_m_x[4u]^_m_x[5u]^_m_x[8u]^_m_x[10u]^_m_x[15u]; \
}while(0)

/* OF : odd round function */
#define __hwport_aria_odd_round_function(m_D,m_RK) do { \
    uint32_t _m_temp[((size_t)def_hwport_aria_block_size)/sizeof(uint32_t)]; \
    __hwport_aria_xor128(m_D,m_RK); \
    __hwport_aria_substitution_layer_type1(_m_temp,m_D); \
    __hwport_aria_diffusion_layer_A(m_D,_m_temp); \
}while(0)

/* EF : even round function */
#define __hwport_aria_even_round_function(m_D,m_RK) do { \
    uint32_t _m_temp[((size_t)def_hwport_aria_block_size)/sizeof(uint32_t)]; \
    __hwport_aria_xor128(m_D,m_RK); \
    __hwport_aria_substitution_layer_type2(_m_temp,m_D); \
    __hwport_aria_diffusion_layer_A(m_D,_m_temp); \
}while(0)

/* make round key */
static void __hwport_make_round_key_aria(void *s_round_key, const void *s_user_key, size_t s_user_key_size)
{
    unsigned int s_rounds;

    uint32_t *s_encrypt_round_key;
    uint32_t *s_decrypt_round_key;

    unsigned int s_index;
    uint32_t s_ksc_be32[ sizeof(__gc_hwport_aria_ksc_he32) / sizeof(uint32_t) ];

    const uint32_t *s_ck1;
    const uint32_t *s_ck2;
    const uint32_t *s_ck3;

    uint32_t s_w[ (((size_t)def_hwport_aria_block_size) / sizeof(uint32_t)) * ((size_t)4u) /* 16u : W0 ~ W3 */];

    /*
        select CK and rounds

        Key size  CK1  CK2  CK3
          128     C1   C2   C3
          192     C2   C3   C1
          256     C3   C1   C2

        Key size     Number of Rounds
          128              12
          192              14
          256              16
    */
    for(s_index = 0u;s_index < (unsigned int)(sizeof(__gc_hwport_aria_ksc_he32) / sizeof(uint32_t));s_index++) {
        s_ksc_be32[s_index] = htonl(__gc_hwport_aria_ksc_he32[s_index]);
    }
    if(s_user_key_size == def_hwport_aria128_user_key_size) { /* 128-bits key */
        s_ck1 = (const uint32_t *)(&s_ksc_be32[0u /* C1 */]);
        s_ck2 = (const uint32_t *)(&s_ksc_be32[4u /* C2 */]);
        s_ck3 = (const uint32_t *)(&s_ksc_be32[8u /* C3 */]);

        s_rounds = (unsigned int)def_hwport_aria128_rounds /* 12 rounds */;
    }
    else if(s_user_key_size == def_hwport_aria192_user_key_size) { /* 192-bits key */
        s_ck1 = (const uint32_t *)(&s_ksc_be32[4u /* C2 */]);
        s_ck2 = (const uint32_t *)(&s_ksc_be32[8u /* C3 */]);
        s_ck3 = (const uint32_t *)(&s_ksc_be32[0u /* C1 */]);

        s_rounds = (unsigned int)def_hwport_aria192_rounds /* 14 rounds */;
    }
    else if(s_user_key_size == def_hwport_aria256_user_key_size) { /* 256-bits key */
        s_ck1 = (const uint32_t *)(&s_ksc_be32[8u /* C3 */]);
        s_ck2 = (const uint32_t *)(&s_ksc_be32[0u /* C1 */]);
        s_ck3 = (const uint32_t *)(&s_ksc_be32[4u /* C2 */]);

        s_rounds = (unsigned int)def_hwport_aria256_rounds /* 16 rounds */;
    }
    else {
        hwport_aria_not_supported();

        return;
    }

    /*
        compute intermediate values W0, W1, W2, W3
          W0 = KL,
          W1 = FO(W0, CK1) ^ KR,
          W2 = FE(W1, CK2) ^ W0,
          W3 = FO(W2, CK3) ^ W1.
    */
    (void)memcpy( /* load KL and KR */
        memset((void *)(&s_w[0u]), 0, sizeof(s_w)),
        s_user_key,
        s_user_key_size
    );

    /* save KR */
    __hwport_aria_mov128(s_w + 8u, s_w + 4u); /* W2(temp) = KR */

    __hwport_aria_mov128(s_w + 4u, s_w + 0u); /* W1 = W0 */
    __hwport_aria_odd_round_function(s_w + 4u, s_ck1); /* W1 = FO(F0, CK1) */
    __hwport_aria_xor128(s_w + 4u, s_w + 8u); /* W1 ^= KR */

    __hwport_aria_mov128(s_w + 8u, s_w + 4u); /* W2 = W1 */
    __hwport_aria_even_round_function(s_w + 8u, s_ck2); /* W2 = FE(W1, CK2) */
    __hwport_aria_xor128(s_w + 8u, s_w + 0u); /* W2 ^= W0 */
    
    __hwport_aria_mov128(s_w + 12u, s_w + 8u); /* W3 = W2 */
    __hwport_aria_odd_round_function(s_w + 12u, s_ck3); /* W3 = FO(W2, CK3) */
    __hwport_aria_xor128(s_w + 12u, s_w + 4u); /* W3 ^= W1 */

    /* convert from big-endian byte order to host byte order */
    for(s_index = 0u;s_index < (unsigned int)(sizeof(s_w) / sizeof(uint32_t));s_index++) {
        s_w[s_index] = ntohl(s_w[s_index]);
    }

    /* point to the encryption round keys */
    s_encrypt_round_key = (uint32_t *)s_round_key;

    /* compute ek1, ..., ek17 as follow
         ek1  = W0 ^(W1 >>> 19),
         ek2  = W1 ^(W2 >>> 19),
         ek3  = W2 ^(W3 >>> 19),
         ek4  = (W0 >>> 19) ^ W3,
         ek5  = W0 ^ (W1 >>> 31),
         ek6  = W1 ^ (W2 >>> 31),
         ek7  = W2 ^ (W3 >>> 31),
         ek8  = (W0 >>> 31) ^ W3,
         ek9  = W0 ^ (W1 <<< 61),
         ek10 = W1 ^ (W2 <<< 61),
         ek11 = W2 ^ (W3 <<< 61),
         ek12 = (W0 <<< 61) ^ W3,
         ek13 = W0 ^ (W1 <<< 31),
         ek14 = W1 ^ (W2 <<< 31),
         ek15 = W2 ^ (W3 <<< 31),
         ek16 = (W0 <<< 31) ^ W3,
         ek17 = W0 ^ (W1 <<< 19).
    */
#if 0L /* too big code */
    __hwport_aria_rol128(s_encrypt_round_key + 0u, s_w + 4u, 109u);
    __hwport_aria_xor128(s_encrypt_round_key + 0u, s_w + 0u);
    __hwport_aria_rol128(s_encrypt_round_key + 4u, s_w + 8u, 109u);
    __hwport_aria_xor128(s_encrypt_round_key + 4u, s_w + 4u);
    __hwport_aria_rol128(s_encrypt_round_key + 8u, s_w + 12u, 109u);
    __hwport_aria_xor128(s_encrypt_round_key + 8u, s_w + 8u);
    __hwport_aria_rol128(s_encrypt_round_key + 12u, s_w + 0u, 109u);
    __hwport_aria_xor128(s_encrypt_round_key + 12u, s_w + 12u);
    __hwport_aria_rol128(s_encrypt_round_key + 16u, s_w + 4u, 97u);
    __hwport_aria_xor128(s_encrypt_round_key + 16u, s_w + 0u);
    __hwport_aria_rol128(s_encrypt_round_key + 20u, s_w + 8u, 97u);
    __hwport_aria_xor128(s_encrypt_round_key + 20u, s_w + 4u);
    __hwport_aria_rol128(s_encrypt_round_key + 24u, s_w + 12u, 97u);
    __hwport_aria_xor128(s_encrypt_round_key + 24u, s_w + 8u);
    __hwport_aria_rol128(s_encrypt_round_key + 28u, s_w + 0u, 97u);
    __hwport_aria_xor128(s_encrypt_round_key + 28u, s_w + 12u);
    __hwport_aria_rol128(s_encrypt_round_key + 32u, s_w + 4u, 61u);
    __hwport_aria_xor128(s_encrypt_round_key + 32u, s_w + 0u);
    __hwport_aria_rol128(s_encrypt_round_key + 36u, s_w + 8u, 61u);
    __hwport_aria_xor128(s_encrypt_round_key + 36u, s_w + 4u);
    __hwport_aria_rol128(s_encrypt_round_key + 40u, s_w + 12u, 61u);
    __hwport_aria_xor128(s_encrypt_round_key + 40u, s_w + 8u);
    __hwport_aria_rol128(s_encrypt_round_key + 44u, s_w + 0u, 61u);
    __hwport_aria_xor128(s_encrypt_round_key + 44u, s_w + 12u);
    __hwport_aria_rol128(s_encrypt_round_key + 48u, s_w + 4u, 31u);
    __hwport_aria_xor128(s_encrypt_round_key + 48u, s_w + 0u);
    if(s_rounds >= ((unsigned int)def_hwport_aria192_rounds)) {
        __hwport_aria_rol128(s_encrypt_round_key + 52u, s_w + 8u, 31u);
        __hwport_aria_xor128(s_encrypt_round_key + 52u, s_w + 4u);
        __hwport_aria_rol128(s_encrypt_round_key + 56u, s_w + 12u, 31u);
        __hwport_aria_xor128(s_encrypt_round_key + 56u, s_w + 8u);
        if(s_rounds >= ((unsigned int)def_hwport_aria256_rounds)) {
            __hwport_aria_rol128(s_encrypt_round_key + 60u, s_w + 0u, 31u);
            __hwport_aria_xor128(s_encrypt_round_key + 60u, s_w + 12u);
            __hwport_aria_rol128(s_encrypt_round_key + 64u, s_w + 4u, 19u);
            __hwport_aria_xor128(s_encrypt_round_key + 64u, s_w + 0u);
        }
    }
#else /* optimize */
    do {
        static const unsigned int cg_rol_shift_index_table[ /* s_rounds + 1 */ ] = {
            109u, 109u, 109u, 109u, 97u, 97u, 97u, 97u, 61u, 61u, 61u, 61u, 31u, 31u, 31u, 31u, 19u
        };                
        unsigned int s_this_index;

        for(s_index = 0u;s_index <= s_rounds;s_index++) {
            s_this_index = s_index << 2;
            __hwport_aria_rol128(s_encrypt_round_key + s_this_index, s_w + ((s_this_index + 4u) & 0x0f), cg_rol_shift_index_table[s_index]);
            __hwport_aria_xor128(s_encrypt_round_key + s_this_index, s_w + (s_this_index & 0x0f));
        }
    }while(0);
#endif
    
    /* convert from host byte order to big-endian byte order */
    for(s_index = 0u;s_index < ((s_rounds + 1u) << 2);s_index++) {
        s_encrypt_round_key[s_index] = htonl(s_encrypt_round_key[s_index]);
    }
   
    /*
        decryption round keys are derived from the encryption round keys

          dk1 = ek{n+1},
          dk2 = A(ek{n}),
          dk3 = A(ek{n-1}),
          ...,
          dk{n}= A(ek2),
          dk{n+1}= ek1.
    */
    s_decrypt_round_key = (uint32_t *)(&s_encrypt_round_key[(s_rounds + 1u) << 2]);
    __hwport_aria_mov128(s_decrypt_round_key + 0u, s_encrypt_round_key + (s_rounds << 2)); /* dk1 = ek[n + 1] */
    for(s_index = 1u;s_index < s_rounds;s_index++) { /* dk2 .. dkn = A(ek[n .. n-r]) */
        __hwport_aria_diffusion_layer_A(s_decrypt_round_key + (s_index << 2), s_encrypt_round_key + ((s_rounds - s_index) << 2));
    }
    __hwport_aria_mov128(s_decrypt_round_key + (s_index << 2), s_encrypt_round_key + 0u); /* dk[n+1] = ek1 */
}

/* aria encrypt/decrypt common */
static void __hwport_do_aria_private(int s_rounds, void *s_data, const void *s_round_key)
{
#if 0L
    const uint32_t *s_round_key_uint32_ptr;
    uint32_t s_p[ ((size_t)def_hwport_aria_block_size) / sizeof(uint32_t) ];
    uint32_t *s_data32_ptr;

    s_round_key_uint32_ptr = (const uint32_t *)s_round_key;

    /* copy the plaintext to the buffer */
    s_data32_ptr = (uint32_t *)s_data;
    __hwport_aria_mov128(s_p, s_data32_ptr);

    /* 11 rounds */
    __hwport_aria_odd_round_function(s_p, s_round_key_uint32_ptr + 0u);
    __hwport_aria_even_round_function(s_p, s_round_key_uint32_ptr + 4u);
    __hwport_aria_odd_round_function(s_p, s_round_key_uint32_ptr + 8u);
    __hwport_aria_even_round_function(s_p, s_round_key_uint32_ptr + 12u);
    __hwport_aria_odd_round_function(s_p, s_round_key_uint32_ptr + 16u);
    __hwport_aria_even_round_function(s_p, s_round_key_uint32_ptr + 20u);
    __hwport_aria_odd_round_function(s_p, s_round_key_uint32_ptr + 24u);
    __hwport_aria_even_round_function(s_p, s_round_key_uint32_ptr + 28u);
    __hwport_aria_odd_round_function(s_p, s_round_key_uint32_ptr + 32u);
    __hwport_aria_even_round_function(s_p, s_round_key_uint32_ptr + 36u);
    __hwport_aria_odd_round_function(s_p, s_round_key_uint32_ptr + 40u);

    if(s_rounds == def_hwport_aria128_rounds) { /* 128-bits user keys require a total of 12 rounds */
        __hwport_aria_xor128(s_p, s_round_key_uint32_ptr + 44);
        __hwport_aria_substitution_layer_type2(s_data32_ptr, s_p);
        __hwport_aria_xor128(s_data32_ptr, s_round_key_uint32_ptr + 48);
    }
    else if(s_rounds == def_hwport_aria192_rounds) { /* 192-bits user keys require a total of 14 rounds */
        __hwport_aria_even_round_function(s_p, s_round_key_uint32_ptr + 44u);
        __hwport_aria_odd_round_function(s_p, s_round_key_uint32_ptr + 48u);

        __hwport_aria_xor128(s_p, s_round_key_uint32_ptr + 52u);
        __hwport_aria_substitution_layer_type2(s_data32_ptr, s_p);
        __hwport_aria_xor128(s_data32_ptr, s_round_key_uint32_ptr + 56u);
    }
    else if(s_rounds == def_hwport_aria256_rounds) { /* 256-bits user keys require a total of 16 rounds */
        __hwport_aria_even_round_function(s_p, s_round_key_uint32_ptr + 44u);
        __hwport_aria_odd_round_function(s_p, s_round_key_uint32_ptr + 48u);
        __hwport_aria_even_round_function(s_p, s_round_key_uint32_ptr + 52u);
        __hwport_aria_odd_round_function(s_p, s_round_key_uint32_ptr + 56u);

        __hwport_aria_xor128(s_p, s_round_key_uint32_ptr + 60u);
        __hwport_aria_substitution_layer_type2(s_data32_ptr, s_p);
        __hwport_aria_xor128(s_data32_ptr, s_round_key_uint32_ptr + 64u);
    }
    else {
        hwport_aria_not_supported();

        return;
    }
#else /* optimize */
    const uint32_t *s_round_key_uint32_ptr;
    uint32_t s_p[ ((size_t)def_hwport_aria_block_size) / sizeof(uint32_t) ];
    unsigned int s_index;
    uint32_t *s_data32_ptr;

    s_round_key_uint32_ptr = (const uint32_t *)s_round_key;

    /* copy the plaintext to the buffer */
    s_data32_ptr = (uint32_t *)s_data;
    __hwport_aria_mov128(s_p, s_data32_ptr);

    for(s_index = 0u;s_index < ((unsigned int)(s_rounds - 1));s_index++) {
        if((s_index & 1u) == 0u) { /* odd round */
            __hwport_aria_odd_round_function(s_p, s_round_key_uint32_ptr + (s_index << 2));
        }
        else { /* even round */
            __hwport_aria_even_round_function(s_p, s_round_key_uint32_ptr + (s_index << 2));
        }
    }
    /* final round */
    __hwport_aria_xor128(s_p, s_round_key_uint32_ptr + (s_index << 2));
    __hwport_aria_substitution_layer_type2(s_data32_ptr, s_p);
    __hwport_aria_xor128(s_data32_ptr, s_round_key_uint32_ptr + ((s_index + 1u) << 2));
#endif
}

/* aria encrypt/decrypt ecb mode common */
static void *__hwport_do_aria_ecb_private(int s_rounds, size_t s_block_size, void *s_data, size_t s_size, const void *s_round_key)
{
    size_t s_offset;

    for(s_offset = (size_t)0u;(s_offset + s_block_size) <= s_size;s_offset += s_block_size) {
        __hwport_do_aria_private(s_rounds, (void *)(((uint8_t *)s_data) + s_offset), s_round_key);
    }

    return(s_data);
}

void *hwport_make_round_key_aria128(void *s_round_key, const void *s_user_key)
{
    __hwport_make_round_key_aria(s_round_key, s_user_key, (size_t)def_hwport_aria128_user_key_size);

    return(s_round_key);
}

void *hwport_encrypt_aria128_ecb(void *s_data, size_t s_size, const void *s_round_key)
{
    return(__hwport_do_aria_ecb_private(def_hwport_aria128_rounds, (size_t)def_hwport_aria128_block_size, s_data, s_size, s_round_key));
}

void *hwport_decrypt_aria128_ecb(void *s_data, size_t s_size, const void *s_round_key)
{
    return(__hwport_do_aria_ecb_private(def_hwport_aria128_rounds, (size_t)def_hwport_aria128_block_size, s_data, s_size, s_round_key));
}

void *hwport_make_round_key_aria192(void *s_round_key, const void *s_user_key)
{
    __hwport_make_round_key_aria(s_round_key, s_user_key, (size_t)def_hwport_aria192_user_key_size);

    return(s_round_key);
}

void *hwport_encrypt_aria192_ecb(void *s_data, size_t s_size, const void *s_round_key)
{
    return(__hwport_do_aria_ecb_private(def_hwport_aria192_rounds, (size_t)def_hwport_aria192_block_size, s_data, s_size, s_round_key));
}

void *hwport_decrypt_aria192_ecb(void *s_data, size_t s_size, const void *s_round_key)
{
    return(__hwport_do_aria_ecb_private(def_hwport_aria192_rounds, (size_t)def_hwport_aria192_block_size, s_data, s_size, s_round_key));
}

void *hwport_make_round_key_aria256(void *s_round_key, const void *s_user_key)
{
    __hwport_make_round_key_aria(s_round_key, s_user_key, (size_t)def_hwport_aria256_user_key_size);

    return(s_round_key);
}

void *hwport_encrypt_aria256_ecb(void *s_data, size_t s_size, const void *s_round_key)
{
    return(__hwport_do_aria_ecb_private(def_hwport_aria256_rounds, (size_t)def_hwport_aria256_block_size, s_data, s_size, s_round_key));
}

void *hwport_decrypt_aria256_ecb(void *s_data, size_t s_size, const void *s_round_key)
{
    return(__hwport_do_aria_ecb_private(def_hwport_aria256_rounds, (size_t)def_hwport_aria256_block_size, s_data, s_size, s_round_key));
}

/* ---- */

#endif

/* vim: set expandtab fdm=marker: */
/* End of source */
