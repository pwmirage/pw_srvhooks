/* SPDX-License-Identifier: MIT
 * Copyright(c) 2019-2020 Darek Stojaczyk for pwmirage.com
 */

#ifndef CJSON_H
#define CJSON_H

#include <stdint.h>
#include <inttypes.h>

#define CJSON_MIN_POOLSIZE 8

enum {
	CJSON_TYPE_NONE = 0,
	CJSON_TYPE_NULL,
	CJSON_TYPE_STRING,
	CJSON_TYPE_BOOLEAN,
	CJSON_TYPE_INTEGER,
	CJSON_TYPE_FLOAT,
	CJSON_TYPE_ARRAY,
	CJSON_TYPE_OBJECT,
};

struct cjson_mempool;

struct cjson {
	struct cjson *parent;
	union {
		struct cjson *next;
		struct cjson_mempool *mem;
	};
	char *key;
	uint32_t type;
	uint32_t count; /**< children count */
	union {
		char *s;
		int64_t i;
		double d;
		struct cjson *a;
	};
};

typedef void (*cjson_parse_arr_stream_cb)(void *ctx, struct cjson *obj);
struct cjson *cjson_parse(char *str);
int cjson_parse_arr_stream(char *str, cjson_parse_arr_stream_cb obj_cb, void *cb_ctx);
struct cjson *cjson_obj(struct cjson *json, const char *key);
int cjson_add_child(struct cjson *parent, struct cjson *child);
void cjson_free(struct cjson *json);

#endif /* CJSON_H */
