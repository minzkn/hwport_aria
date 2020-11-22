/*
    Copyright (C) HWPORT.COM
    All rights reserved.
    Author: JAEHYUK CHO <mailto:minzkn@minzkn.com>
*/

#if !defined(_ISOC99_SOURCE)
# define _ISOC99_SOURCE (1L)
#endif

#if !defined(_GNU_SOURCE)
# define _GNU_SOURCE (1L)
#endif

#include <sys/types.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

#include "hwport_aria.h"

static void hwport_dump(const char *s_title, const void *s_data, size_t s_size);

static void test_aria(const char *s_title, size_t s_block_size, size_t s_user_key_size, size_t s_round_key_size, hwport_make_round_key_handler_t s_make_round_key_handler, hwport_encrypt_handler_t s_encrypt_handler, hwport_decrypt_handler_t s_decrypt_handler);

int main(int s_argc, char **s_argv);

static void hwport_dump(const char *s_title, const void *s_data, size_t s_size)
{
    size_t s_o,s_w,s_i;uint8_t s_b[17];
    (void)fprintf(stdout, "%s:\n", s_title);
    s_b[16]='\0';s_o=(size_t)0u;
    while(s_o<s_size){
        s_w=(s_size-s_o)<((size_t)16u)?(s_size-s_o):((size_t)16u);
        printf("%08lX",(unsigned long)s_o);for(s_i=(size_t)0u;s_i<s_w;s_i++){if(s_i==((size_t)8u))printf(" | ");else printf(" ");
        s_b[s_i]=*(((const uint8_t *)(s_data))+s_o+s_i);printf("%02X",(unsigned int)s_b[s_i]);if((isprint(s_b[s_i])==0)||(s_b[s_i]<' '))s_b[s_i]='.';}
    while(s_i<16){if(s_i==8)printf("     ");else printf("   ");s_b[s_i]=' ';s_i++;}
    printf(" [%s]\n",(char *)s_b);s_o+=(size_t)16u;}
    (void)fprintf(stdout, "\n");
}

static void test_aria(const char *s_title, size_t s_block_size, size_t s_user_key_size, size_t s_round_key_size, hwport_make_round_key_handler_t s_make_round_key_handler, hwport_encrypt_handler_t s_encrypt_handler, hwport_decrypt_handler_t s_decrypt_handler)
{
    static const char s_data[] = {
        "ARIA encrypt/decrypt library/example source\n"
        "Copyright (C) JAEHYUK CHO\n"
        "All rights reserved.\n"
        "Code by JaeHyuk Cho <mailto:minzkn@minzkn.com>\n"
    };

    size_t s_data_size, s_padding_data_size;
    void *s_padding_data;

    uint8_t s_user_key[ def_hwport_aes_max_user_key_size ];
    uint8_t s_round_key[ def_hwport_aes_max_round_key_size ];

    (void)fprintf(stdout, "\x1b[1;33m%s\x1b[0m\n~~~~~~~~~~~~~~~~\n\n", s_title);

    /* password */
    (void)memset(&s_user_key[0], 0, sizeof(s_user_key));
    (void)strncpy((char *)(&s_user_key[0]), "ABCDEFGHIJKLMNOPQRSTUVWX", sizeof(s_user_key));
 
    hwport_dump("user key", &s_user_key[0], s_user_key_size);

    (void)(*s_make_round_key_handler)(&s_round_key[0], &s_user_key[0]);

    /* padding process */
    s_data_size = sizeof(s_data);
    s_padding_data_size = s_data_size + (s_block_size - 1);
    s_padding_data_size -= s_padding_data_size % s_block_size;
    s_padding_data = malloc(s_padding_data_size);
    if(s_padding_data == ((void *)0)) {
        (void)fprintf(stderr, "not enough memory !\n");
        return;
    }
    (void)memcpy(s_padding_data, s_data, s_data_size);
    if((s_padding_data_size - s_data_size) > ((size_t)0u)) { /* zero padding */
        (void)memset(((uint8_t *)s_padding_data) + s_data_size, 0, s_padding_data_size - s_data_size);
    }
 
    hwport_dump("data", &s_data[0], s_data_size);

    (void)fprintf(stdout, "data_size + pad_size = %lu + %lu = %lu [%lux%lu]\n", (unsigned long)s_data_size, (unsigned long)(s_padding_data_size - s_data_size), (unsigned long)s_padding_data_size, (unsigned long)(s_padding_data_size / s_block_size), (unsigned long)s_block_size); 

    hwport_dump("encrpyt",
        (*s_encrypt_handler)(s_padding_data, s_padding_data_size, &s_round_key[0 /* encrypt round key */]),
        s_padding_data_size
    );
 
    hwport_dump("decrypt",
        (*s_decrypt_handler)(s_padding_data, s_padding_data_size, &s_round_key[s_round_key_size >> 1 /* decrypt round key */]),
        s_data_size
    );

    free((void *)s_padding_data);
}

int main(int s_argc, char **s_argv)
{
    (void)s_argc;
    (void)s_argv;

#if 1L
    /*
        ARIA128-ECB Test vector
        ======================

        Set 1 vector 1
            mode=aria-128
            key=00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff
            plain=11 11 11 11 aa aa aa aa 11 11 11 11 bb bb bb bb
            cipher=c6 ec d0 8e 22 c3 0a bd b2 15 cf 74 e2 07 5e 6e
    */
    do { /* ARIA128 ECB */
        uint8_t s_key[ def_hwport_aria128_user_key_size ] = {
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
        };
        uint8_t s_data[ /* def_hwport_aria128_block_size * n */ ] = {
            0x11, 0x11, 0x11, 0x11, 0xaa, 0xaa, 0xaa, 0xaa, 0x11, 0x11, 0x11, 0x11, 0xbb, 0xbb, 0xbb, 0xbb
        };
        const uint8_t s_cipher[ /* def_hwport_aria128_block_size * n */ ] = {
            0xc6, 0xec, 0xd0, 0x8e, 0x22, 0xc3, 0x0a, 0xbd, 0xb2, 0x15, 0xcf, 0x74, 0xe2, 0x07, 0x5e, 0x6e
        };
        uint8_t s_round_key[ def_hwport_aria128_round_key_size ];
   
        (void)hwport_dump("key", (const void *)(&s_key[0]), sizeof(s_key));

        (void)hwport_make_round_key_aria128((void *)(&s_round_key[0]), (const void *)(&s_key[0]));
        (void)hwport_dump("round_key", (const void *)(&s_round_key[0]), sizeof(s_round_key));

        (void)hwport_dump("plain", (const void *)(&s_data[0]), sizeof(s_data));

        (void)hwport_encrypt_aria128_ecb(
            (void *)(&s_data[0]),
            sizeof(s_data),
            (const void *)(&s_round_key[def_hwport_aria128_encrypt_round_key_offset])
        );
        (void)fprintf(stdout, "cipher(encrypted) %s:\n",
            (memcmp((const void *)(&s_data[0]), (const void *)(&s_cipher[0]), sizeof(s_data)) == 0) ? "PASSED" : "FAILED"
        );
        (void)hwport_dump("===>", (const void *)(&s_data[0]), sizeof(s_data));

        (void)hwport_decrypt_aria128_ecb(
            (void *)(&s_data[0]),
            sizeof(s_data),
            (const void *)(&s_round_key[def_hwport_aria128_decrypt_round_key_offset])
        );
        (void)hwport_dump("plain(decrypted)", (const void *)(&s_data[0]), sizeof(s_data));
    }while(0);
#endif

#if 1L
    /*
        ARIA192-ECB Test vector
        ======================

        Set 1 vector 1
            mode=aria-192
            key=00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff 00 11 22 33 44 55 66 77
            plain=11 11 11 11 aa aa aa aa 11 11 11 11 bb bb bb bb
            cipher=8d 14 70 62 5f 59 eb ac b0 e5 5b 53 4b 3e 46 2b
    */
    do { /* ARIA192 ECB */
        uint8_t s_key[ def_hwport_aria192_user_key_size ] = {
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77
        };
        uint8_t s_data[ /* def_hwport_aria192_block_size * n */ ] = {
            0x11, 0x11, 0x11, 0x11, 0xaa, 0xaa, 0xaa, 0xaa, 0x11, 0x11, 0x11, 0x11, 0xbb, 0xbb, 0xbb, 0xbb
        };
        const uint8_t s_cipher[ /* def_hwport_aria192_block_size * n */ ] = {
            0x8d, 0x14, 0x70, 0x62, 0x5f, 0x59, 0xeb, 0xac, 0xb0, 0xe5, 0x5b, 0x53, 0x4b, 0x3e, 0x46, 0x2b
        };
        uint8_t s_round_key[ def_hwport_aria192_round_key_size ];
   
        (void)hwport_dump("key", (const void *)(&s_key[0]), sizeof(s_key));

        (void)hwport_make_round_key_aria192((void *)(&s_round_key[0]), (const void *)(&s_key[0]));
        (void)hwport_dump("round_key", (const void *)(&s_round_key[0]), sizeof(s_round_key));

        (void)hwport_dump("plain", (const void *)(&s_data[0]), sizeof(s_data));

        (void)hwport_encrypt_aria192_ecb(
            (void *)(&s_data[0]),
            sizeof(s_data),
            (const void *)(&s_round_key[def_hwport_aria192_encrypt_round_key_offset])
        );
        (void)fprintf(stdout, "cipher(encrypted) %s:\n",
            (memcmp((const void *)(&s_data[0]), (const void *)(&s_cipher[0]), sizeof(s_data)) == 0) ? "PASSED" : "FAILED"
        );
        (void)hwport_dump("===>", (const void *)(&s_data[0]), sizeof(s_data));

        (void)hwport_decrypt_aria192_ecb(
            (void *)(&s_data[0]),
            sizeof(s_data),
            (const void *)(&s_round_key[def_hwport_aria192_decrypt_round_key_offset])
        );
        (void)hwport_dump("plain(decrypted)", (const void *)(&s_data[0]), sizeof(s_data));
    }while(0);
#endif

#if 1L
    /*
        ARIA256-ECB Test vector
        ======================

        Set 1 vector 1
            mode=aria-256
            key=00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff
            plain=11 11 11 11 aa aa aa aa 11 11 11 11 bb bb bb bb
            cipher=58 a8 75 e6 04 4a d7 ff fa 4f 58 42 0f 7f 44 2d
    */
    do { /* ARIA256 ECB */
        uint8_t s_key[ def_hwport_aria256_user_key_size ] = {
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
        };
        uint8_t s_data[ /* def_hwport_aria256_block_size * n */ ] = {
            0x11, 0x11, 0x11, 0x11, 0xaa, 0xaa, 0xaa, 0xaa, 0x11, 0x11, 0x11, 0x11, 0xbb, 0xbb, 0xbb, 0xbb
        };
        const uint8_t s_cipher[ /* def_hwport_aria256_block_size * n */ ] = {
            0x58, 0xa8, 0x75, 0xe6, 0x04, 0x4a, 0xd7, 0xff, 0xfa, 0x4f, 0x58, 0x42, 0x0f, 0x7f, 0x44, 0x2d
        };
        uint8_t s_round_key[ def_hwport_aria256_round_key_size ];
   
        (void)hwport_dump("key", (const void *)(&s_key[0]), sizeof(s_key));

        (void)hwport_make_round_key_aria256((void *)(&s_round_key[0]), (const void *)(&s_key[0]));
        (void)hwport_dump("round_key", (const void *)(&s_round_key[0]), sizeof(s_round_key));

        (void)hwport_dump("plain", (const void *)(&s_data[0]), sizeof(s_data));

        (void)hwport_encrypt_aria256_ecb(
            (void *)(&s_data[0]),
            sizeof(s_data),
            (const void *)(&s_round_key[def_hwport_aria256_encrypt_round_key_offset])
        );
        (void)fprintf(stdout, "cipher(encrypted) %s:\n",
            (memcmp((const void *)(&s_data[0]), (const void *)(&s_cipher[0]), sizeof(s_data)) == 0) ? "PASSED" : "FAILED"
        );
        (void)hwport_dump("===>", (const void *)(&s_data[0]), sizeof(s_data));

        (void)hwport_decrypt_aria256_ecb(
            (void *)(&s_data[0]),
            sizeof(s_data),
            (const void *)(&s_round_key[def_hwport_aria256_decrypt_round_key_offset])
        );
        (void)hwport_dump("plain(decrypted)", (const void *)(&s_data[0]), sizeof(s_data));
    }while(0);
#endif

    test_aria(
        "ARIA128 test",
        (size_t)def_hwport_aria128_block_size,
        (size_t)def_hwport_aria128_user_key_size,
        (size_t)def_hwport_aria128_round_key_size,
        &hwport_make_round_key_aria128,
        &hwport_encrypt_aria128_ecb,
        &hwport_decrypt_aria128_ecb
    );
    test_aria(
        "ARIA192 test",
        (size_t)def_hwport_aria192_block_size,
        (size_t)def_hwport_aria192_user_key_size,
        (size_t)def_hwport_aria192_round_key_size,
        &hwport_make_round_key_aria192,
        &hwport_encrypt_aria192_ecb,
        &hwport_decrypt_aria192_ecb
    );
    test_aria(
        "ARIA256 test",
        (size_t)def_hwport_aria256_block_size,
        (size_t)def_hwport_aria256_user_key_size,
        (size_t)def_hwport_aria256_round_key_size,
        &hwport_make_round_key_aria256,
        &hwport_encrypt_aria256_ecb,
        &hwport_decrypt_aria256_ecb
    );

    return(EXIT_SUCCESS);
}

/* vim: set expandtab: */
/* End of source */
