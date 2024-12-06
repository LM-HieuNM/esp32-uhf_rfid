/*
 * typedefs.h
 *
 *  Created on: Apr 19, 2024
 *      Author: HieuNM
 */

#ifndef MAIN_TYPEDEFS_H_
#define MAIN_TYPEDEFS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "stddef.h"

typedef unsigned char           byte_t;     // 1 byte
typedef unsigned short          word_t;     // 2 byte
typedef unsigned long           dword_t;    // 8 byte
typedef unsigned int            uint_t;     // 4 byte
typedef char                    char_t;     // 1 byte
//typedef void                    void;

typedef byte_t*                 byte_p;
typedef word_t*                 word_p;
typedef dword_t*                dword_p;
typedef uint_t*                 uint_p;
typedef char_t*                 char_p;
typedef void*                 void_p;

typedef unsigned char           u8_t;       // 1 byte
typedef unsigned char*          u8_p;       // 1 byte

typedef signed char             i8_t;       // 1 byte
typedef signed char*            i8_p;       // 1 byte

typedef unsigned char**         u8_pp;

typedef unsigned short          u16_t;      // 2 byte
typedef unsigned short*         u16_p;      // 2 byte

typedef signed short            i16_t;      // 2 byte
typedef signed short*           i16_p;      // 2 byte

typedef unsigned int            uint_t;
typedef signed int              int_t;

typedef unsigned int*           uint_p;
typedef signed int*             int_p;

typedef float                   flo_t;
typedef float*                  flo_p;

typedef double                  dob_t;
typedef double*                 dob_p;

typedef const char              const_char_t;
typedef const char*             const_char_p;

typedef const void              const_void;
typedef const void*             const_void_p;

typedef void const              void_const_t;
typedef void const*             void_const_p;


typedef uint32_t            	u32_t;      // 4 byte
typedef uint64_t       			u64_t;

typedef signed int              i32_t;      // 4 byte
typedef signed long int         i64_t;

typedef unsigned int*           u32_p;      // 4 byte
typedef unsigned long int*      u64_p;

typedef signed int*             i32_p;      // 4 byte
typedef signed long int*        i64_p;

#ifndef __cplusplus
typedef unsigned char           bool_t;
#ifndef TRUE
#define TRUE                    (1)
#endif
#ifndef FALSE
#define FALSE                   (0)
#endif
#else
typedef bool                    bool_t;
#ifndef TRUE
#define TRUE                    true
#endif
#ifndef FALSE
#define FALSE                   false
#endif
#endif

#ifndef NULL
#define NULL                    (0)
#endif

#ifndef BV
#define BV(n)                   (1 << (n))
#endif

#ifndef ST
#define ST(x)                   do { x } while (__LINE__ == -1)
#endif

#ifndef HI_UINT16
#define HI_UINT16(a)            (((a) >> 8) & 0xFF)
#endif

#ifndef LO_UINT16
#define LO_UINT16(a)            ((a) & 0xFF)
#endif

#ifndef MERGE
#define MERGE(h,l)              (((h) << 8) | (l))
#endif

#ifndef UNUSED
#define UNUSED(x)               (x) = (x)
#endif

#ifdef __cplusplus
}
#endif

#endif /* MAIN_TYPEDEFS_H_ */
