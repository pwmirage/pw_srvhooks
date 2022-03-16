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
	char unk[8];
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


void __cdecl (*pw_setprogname)(char *name) = (void *)0x8146814;

static void __attribute__((constructor))
init(void)
{
	fprintf(stderr, "preload start\n");
	pw_setprogname("gamedbd");
	patch_mem_static_init();
	fprintf(stderr, "preload done\n");
}
