/* SPDX-License-Identifier: MIT
 * Copyright(c) 2021-2022 Darek Stojaczyk for pwmirage.com
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdbool.h>
#include <wchar.h>
#include <locale.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <assert.h>
#include <sys/mman.h>
#include <assert.h>
#include <math.h>
#include <link.h>

#include "memory.h"

#define __cdecl __attribute__((__cdecl__))
#define __thiscall __attribute__((__thiscall__))
#define __stdcall __attribute__((__stdcall__))

struct octets {
	void *super;
	void *data;
};

static size_t __cdecl
(*octets_size)(struct octets *o) = (void *)0x804905a;

static struct octets * __cdecl
(*octets_resize)(struct octets *this, size_t size) = (void *)0x80490ba;

static struct octets * __cdecl
(*octets_copy)(struct octets *dst, struct octets *src) = (void *)0x80a97e2;

static char *
octets_get_str16(struct octets *o)
{
	static char ret[128];
	int16_t *str = o->data;
	int len = octets_size(o);
	int i = 0;

	while (len--) {
		ret[i++] = *str;
		str++;
	}

	ret[i] = 0;

	return ret;
}

static void
octets_set_str(struct octets *o, const char *str)
{
	int16_t *dst;
	int i = 0;

	octets_resize(o, strlen(str) * 2);

	dst = o->data;
	while (*str) {
		dst[i++] = *str;
		str++;
	}
}

struct octets_stream {
	struct octets data;
	size_t pos;
	size_t backup_pos;
};

struct vector {
	char unk[16];
};

struct role_base {
	char version;
	int id;
	struct octets name;
	int race;
	int cls;
	char gender;
	struct octets custom_data;
	struct octets config_data;
	int custom_stamp;
	char status;
	int delete_time;
	int create_time;
	int lastlogin_time;
	struct vector forbid;
	struct octets help_states;
	int reserved1;
	int reserved2;
	int reserved3;
};

static void __stdcall
hooked_put_role_base(void *_dst, void *_src)
{
	struct role_base *src = _src + 0x10;
	struct role_base *dst = _dst - 0xa0 - 0x34;

	dst->gender = src->gender;
	dst->custom_stamp = src->custom_stamp;
}

PATCH_MEM(0x806c27b, 9,
	"push eax;"
	"push ebp;"
	"call 0x%x", hooked_put_role_base);

static void __cdecl
(*pw_get_role_base)(void *unk1, void *role_id_arg, void *role_base_data, void *unk2, int unk3) = (void *)0x806c93e;

static struct octet_stream * __cdecl
(*pw_build_friend_info)(void *info, struct octet_stream *stream) = (void *)0x80e7fce;

static struct octet_stream * __cdecl
hooked_build_friend_info(void *info, struct octet_stream *stream)
{
	struct octet_stream *ret = pw_build_friend_info(info, stream);
	int rid = *(int *)(info + 4);
	struct octets *name = (void *)(info + 0xc);

	struct {
		void *super;
		int id;
	} role_id_arg;
	void __cdecl (*role_id_arg_ctor)(void *role_id, int id) = (void *)0x805a838;
	role_id_arg_ctor(&role_id_arg, rid);

	struct {
		void *super;
		int retcode;
		void *role_base_super;
		struct role_base data;
	} role_base_data;
	void __cdecl (*role_base_data_ctor)(void *role_base, int retcode) = (void *)0x805b696;
	role_base_data_ctor(&role_base_data, 0);

	pw_get_role_base(NULL, &role_id_arg, &role_base_data, NULL, 0);
	if (role_base_data.retcode == 0) {
		octets_copy(name, &role_base_data.data.name);
	}

	return ret;
}

TRAMPOLINE_FN(&pw_build_friend_info, 6, hooked_build_friend_info);

void __cdecl (*pw_setprogname)(char *name) = (void *)0x8146814;

static void __attribute__((constructor))
init(void)
{
	fprintf(stderr, "preload start\n");
	pw_setprogname("gamedbd");
	patch_mem_static_init();
	fprintf(stderr, "preload done\n");
}
