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

PATCH_MEM(0x80f894c, 1, "ret;");

struct octets {
	void *super;
	void *data;
};

static void __cdecl
(*octets_ctor)(struct octets *o) = (void *)0x805b7c2;

static size_t __cdecl
(*octets_size)(struct octets *o) = (void *)0x804f138;

static struct octets * __cdecl
(*octets_resize)(struct octets *this, size_t size) = (void *)0x808c15e;

struct vector {
	void *start;
	void *finish;
	void *end_of_storage;
};

struct i_vector {
	void *super;
	struct vector data;
};

struct friend_info {
	void *super;
	int rid;
	char cls;
	char gid;
	char reserved[2];
	struct octets name;
};

struct userinfo {
	int roleid;
	unsigned sid;
	unsigned localsid;
	int status;
	char unk1[436];
	struct octets name;
	char unk2[12];
	int friend_ver;
	struct i_vector friendgroups;
	struct i_vector friendlist;
};

struct userinfo * __cdecl
(*pw_find_user)(void *user_mgr, int userid) = (void *)0x806b950;

static char *
octets_get_str16(struct octets *o)
{
	static char ret[128];
	int16_t *str = o->data;
	int len = octets_size(o) / 2;
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

static void * (*pw_get_user_mgr)(void) = (void *)0x806b93a;
static bool __cdecl (*pw_find_user_id)(void *user_mgr, struct octets *name, int *id) = (void *)0x811575a;

struct private_msg {
	void *super;
	void *unk;

	uint8_t channel;
	uint8_t emote;
	uint8_t reserved1;
	uint8_t reserved2;

	struct octets src_name;
	int32_t src_id;

	struct octets dst_name;
	int32_t dst_id;

	struct octets msg;
};

static void __cdecl (*pw_erase_role_name)(void *user_mgr, struct octets *name) = (void *)(0x80730b6);
static void __cdecl (*pw_insert_role_name)(void *user_mgr, struct octets *name, int roleid) = (void *)(0x811582c);

static void *(*pw_get_gdelivery_server)(void) = (void *)0x805734e;
static bool (*pw_remove_role_cache)(void *cachemap, int *roleid) = (void *)0x811a28e;

static struct userinfo * __cdecl
hooked_find_private_chat_user(void *user_mgr, struct private_msg *msg)
{
	char *str;
	char *argv[6] = {};
	int argc = 6;
	int rc;

	if (msg->channel != 14 || msg->dst_id != 1 || msg->src_id != 2) {
		/* continue processing it */
		return pw_find_user(user_mgr, msg->src_id & ~0xf);
	}

	str = octets_get_str16(&msg->msg);
	fprintf(stderr, "[gdelivery] meta msg: %s\n", str);

	rc = split_string_to_words(str, " ", argv, &argc);
	if (rc != 0 || argc == 0) {
		goto out;
	}

	if (strcmp(argv[0], "renamerole") == 0) {
		if (argc != 4) {
			goto out;
		}

		int roleid = atoi(argv[1]);
		const char *oldname = argv[2];
		const char *newname = argv[3];

		struct octets o_name;
		octets_ctor(&o_name);

		octets_set_str(&o_name, oldname);
		pw_erase_role_name(user_mgr, &o_name);

		octets_set_str(&o_name, newname);
		pw_insert_role_name(user_mgr, &o_name, roleid);

		pw_remove_role_cache(pw_get_gdelivery_server() + 0x20, &roleid);
	} else if (strcmp(argv[0], "flushrolecache") == 0) {
		if (argc != 2) {
			goto out;
		}

		int roleid = atoi(argv[1]);
		pw_remove_role_cache(pw_get_gdelivery_server() + 0x20, &roleid);
	}

out:
	return NULL;
}

PATCH_MEM(0x80f9849, 1, "push edx;");
PATCH_JMP32(0x80f9856, hooked_find_private_chat_user);

/* don't mask GMs in private chat */
PATCH_MEM(0x80f98bd, 7, "jmp 0x%x;", 0x080f990c);

static void __attribute__((constructor))
init(void)
{
	fprintf(stderr, "preload start\n");
	patch_mem_static_init();
	fprintf(stderr, "preload done\n");
}
