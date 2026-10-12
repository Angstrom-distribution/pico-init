/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The subset of upstream's private _sd-common.h (systemd.git
 * src/systemd/_sd-common.h) that the public sd-*.h headers here need. Never
 * include this directly, only through a public sd-*.h.
 */

#pragma once

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* Same guard as upstream's private header, so a stray direct #include fails
 * the same way it would against a real libsystemd install. */
#if defined(__INCLUDE_LEVEL__) && __INCLUDE_LEVEL__ <= 1 && !defined(__COVERITY__) && \
                !defined(__clang_analyzer__)
#        error "Do not include _sd-common.h directly; it is a private header."
#endif

#ifndef _sd_printf_
#        if __GNUC__ >= 4
#                define _sd_printf_(a, b) __attribute__((__format__(printf, a, b)))
#        else
#                define _sd_printf_(a, b)
#        endif
#endif

#ifndef _sd_sentinel_
#        define _sd_sentinel_ __attribute__((__sentinel__))
#endif

#ifndef _sd_deprecated_
#        if __GNUC__ >= 6
#                define _sd_deprecated_ __attribute__((__deprecated__))
#        else
#                define _sd_deprecated_
#        endif
#endif

#ifndef _SD_STRINGIFY
#        define _SD_XSTRINGIFY(x) #x
#        define _SD_STRINGIFY(x) _SD_XSTRINGIFY(x)
#endif

/* sd-id128.h's out-buffer parameters: char s[_SD_ARRAY_STATIC N]. */
#ifndef _SD_ARRAY_STATIC
#        if __STDC_VERSION__ >= 199901L && !defined(__cplusplus)
#                define _SD_ARRAY_STATIC static
#        else
#                define _SD_ARRAY_STATIC
#        endif
#endif

#ifndef _SD_BEGIN_DECLARATIONS
#        ifdef __cplusplus
#                define _SD_BEGIN_DECLARATIONS \
                        extern "C" {           \
                        struct _sd_useless_struct_to_allow_trailing_semicolon_
#        else
#                define _SD_BEGIN_DECLARATIONS struct _sd_useless_struct_to_allow_trailing_semicolon_
#        endif
#endif

#ifndef _SD_END_DECLARATIONS
#        ifdef __cplusplus
#                define _SD_END_DECLARATIONS \
                        }                    \
                        struct _sd_useless_cpp_struct_to_allow_trailing_semicolon_
#        else
#                define _SD_END_DECLARATIONS struct _sd_useless_struct_to_allow_trailing_semicolon_
#        endif
#endif

#ifndef _SD_DEFINE_POINTER_CLEANUP_FUNC
#        define _SD_DEFINE_POINTER_CLEANUP_FUNC(type, func) \
                static __inline__ void func##p(type **p) {  \
                        if (*p)                             \
                                func(*p);                   \
                }                                           \
                struct _sd_useless_struct_to_allow_trailing_semicolon_
#endif

/* Public enums carry two members at the ends of the int64_t range so they are
 * 64 bits wide and can grow without an ABI break. */
#ifndef _SD_ENUM_FORCE_S64
#        define _SD_ENUM_FORCE_S64(id) _SD_##id##_INT64_MIN = INT64_MIN, _SD_##id##_INT64_MAX = INT64_MAX
#endif

#ifndef _SD_ENUM_TYPE_S64
#        if ((__GNUC__ >= 14) || (__STDC_VERSION__ >= 202311L)) && !defined(__cplusplus)
#                define _SD_ENUM_TYPE_S64(id) id : int64_t
#        else
#                define _SD_ENUM_TYPE_S64(id) id
#        endif
#endif
