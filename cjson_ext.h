/* SPDX-License-Identifier: MIT
 * Copyright(c) 2019-2020 Darek Stojaczyk for pwmirage.com
 */

#ifndef CJSON_EXT_H
#define CJSON_EXT_H

#include <stdarg.h>

#include "cjson.h"

/**
 * Slightly more controversial functions which didn't make it into
 * the normal header.
 */

struct cjson *cjson_js_ext(size_t argc, ...);

#define PP_NARG(...) \
	PP_NARG_(__VA_ARGS__,PP_RSEQ_N())
#define PP_NARG_(...) \
	PP_ARG_N(__VA_ARGS__)
#define PP_ARG_N(_1, _2, _3, _4, _5, _6, _7, _8, N, ...) N
#define PP_RSEQ_N() 8, 7, 6, 5, 4, 3, 2, 1, 0

#define JS(...) cjson_js_ext(PP_NARG(__VA_ARGS__), __VA_ARGS__)
#define JSi(...) JS(__VA_ARGS__)->i
#define JSf(...) JS(__VA_ARGS__)->d
#define JSs(...) JS(__VA_ARGS__)->s

#endif /* CJSON_EXT_H */
