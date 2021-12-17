/* SPDX-License-Identifier: MIT
 * Copyright(c) 2021 Darek Stojaczyk for pwmirage.com
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

#include "common.h"
#include "avl.h"
#include "cjson.h"
#include "cjson_ext.h"

#define PAGE_SIZE 4096
#define MIRAGE_CELESTONE_ID 11208

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#define __cdecl __attribute__((__cdecl__))
#define __thiscall __attribute__((__thiscall__))
#define __stdcall __attribute__((__stdcall__))

struct pw_item {
	uint32_t type;
	uint32_t count;
	uint32_t pile_limit;
	uint32_t equip_mask;
	uint32_t proc_type;
	uint32_t classid;
	struct
	{
		uint32_t guid1;
		uint32_t guid2;
	} guid;
	uint32_t price;
	uint32_t expire_date;
	uint32_t content_length;
	char *item_content;
};

static void
patch_mem(uintptr_t addr, const char *buf, unsigned num_bytes)
{
	void *page = (void *)(addr & ~(PAGE_SIZE - 1));
	unsigned mprot_bytes = (addr & (PAGE_SIZE - 1)) + num_bytes;
	char tmp[1024];
	size_t tmplen = 0;
	int i;

	for (i = 0; i < num_bytes; i++) {
		tmplen += snprintf(tmp + tmplen, MAX(0, sizeof(tmp) - tmplen), "0x%x ", (unsigned char)buf[i]);
	}
	fprintf(stderr, "patching %d bytes at 0x%x: %s\n", num_bytes, addr, tmp);

	mprotect(page, mprot_bytes, PROT_READ | PROT_WRITE);
	memcpy((void *)addr, buf, num_bytes);
	mprotect(page, mprot_bytes, PROT_READ | PROT_EXEC);
}

void
u32_to_str(char *buf, uint32_t u32)
{
	union {
		char c[4];
		uint32_t u;
	} u;

	u.u = u32;
	buf[0] = u.c[0];
	buf[1] = u.c[1];
	buf[2] = u.c[2];
	buf[3] = u.c[3];
}

void
patch_mem_u32(uintptr_t addr, uint32_t u32)
{
	union {
		char c[4];
		uint32_t u;
	} u;

	u.u = u32;
	patch_mem(addr, u.c, 4);
}

void
patch_jmp32(uintptr_t addr, uintptr_t fn)
{
	uint8_t op = *(char *)addr;
	if (op != 0xe9 && op != 0xe8) {
		fprintf(stderr, "Opcode %X at 0x%x is not a valid JMP/CALL", op, addr);
		return;
	}

	patch_mem_u32(addr + 1, fn - addr - 5);
}

void
trampoline_fn(void **orig_fn, unsigned replaced_bytes, void *fn)
{
	uint32_t addr = (uintptr_t)*orig_fn;
	char orig_code[32];
	char buf[32];
	char *orig;

	memcpy(orig_code, (void *)addr, replaced_bytes);

	orig = calloc(1, (replaced_bytes + 5 + 0xFFF) & ~0xFFF);
	if (orig == NULL) {
		assert(false);
		return;
	}

	/* copy original code to a buffer */
	memcpy(orig, (void *)addr, replaced_bytes);
	/* follow it by a jump to the rest of original code */
	orig[replaced_bytes] = 0xe9;
	u32_to_str(orig + replaced_bytes + 1, (uint32_t)(uintptr_t)addr + replaced_bytes - (uintptr_t)orig - replaced_bytes - 5);

	/* patch the original code to do a jump */
	buf[0] = 0xe9;
	u32_to_str(buf + 1, (uint32_t)(uintptr_t)fn - addr - 5);
	memset(buf + 5, 0x90, replaced_bytes - 5);
	patch_mem(addr, buf, replaced_bytes);

	mprotect(orig, (replaced_bytes + 5 + 0xFFF) & ~0xFFF, PROT_READ | PROT_EXEC);

	*orig_fn = orig;
}

static void *g_timer = (void *)0x8797700;
static unsigned (* get_systime)(void *timer) = (void *)0x821b1dc;

static void
setup_expiration(void *item)
{
	unsigned time = (*(unsigned *)(item + 0x10)) >> (32 - 12);
	if (time) {
		time = get_systime(g_timer) + time * 300;
		*(unsigned *)(item + 0x24) = time;
	}
}

static void * (*org_generate_item_for_drop_fn)(void *this, uint param_1,void *param_2,uint param_3) = (void *)0x81ed87c;

static void *
generate_item_for_drop(void *this, unsigned param_1, void *param_2, unsigned param_3)
{
	void *ret = org_generate_item_for_drop_fn(this, param_1, param_2, param_3);
	if (!ret) {
		return ret;
	}

	setup_expiration(ret);
	return ret;
}

static void * (*org_generate_item_from_player_fn)(void *this, uint param_1,void *param_2,uint param_3) = (void *)0x81ed8f0;

static void *
generate_item_from_player(void *this, unsigned param_1, void *param_2, unsigned param_3)
{
	void *ret = org_generate_item_from_player_fn(this, param_1, param_2, param_3);
	if (!ret) {
		return ret;
	}

	setup_expiration(ret);
	return ret;
}

static void __cdecl (*MSG)(char *buf) = (void *)0x806271c;

static void * (*get_server_xid)(void) = (void *)0x80a4272;

static void __cdecl (*build_message)(void *msg, int message, void *target_xid, void *source_xid, float pos[3], int param, void *content, size_t content_length) = (void *)0x806275a;

static void __cdecl (*post_lazy_message)(void *world, void *msg) = (void *)0x80885b0;

static unsigned __cdecl (*get_npc_id)(void *gnpc_imp) = (void *)0x80a41c0;

static void __cdecl (*org_gnpc_imp_drop_item_fn)(void *gnpc_imp, void *killer_xid, int player_lvl, int team_id, int team_seq, int wallow_level) = (void *)0x80a241a;

/* it's actually a cdecl, but we don't want to clean the stack in our hook */
static bool __stdcall (*org_gnpc_imp_drop_item_from_global_fn)(void *gnpc_imp, void *killer_xid, int player_lvl, int team_id, int team_seq, int wallow_level) = (void *)0x80a1da2;

/* rand 0.0 to 1.0 */
static double (*rand_uniform)(void) = (void *)0x8087276;

struct pw_avl *g_mirages_per_mob;

struct mirages_per_mob {
	unsigned id;
	int min;
	int max;
};

static bool __cdecl
hooked_gnpc_imp_drop_item_from_global_fn(void *gnpc_imp, void *killer_xid, int player_lvl,
		int team_id, int team_seq, int wallow_level)
{
	char msg[48];
	int dropped_items[36];
	unsigned mob_id = get_npc_id(gnpc_imp);

	struct mirages_per_mob *mg = pw_avl_get(g_mirages_per_mob, mob_id);
	while (mg && mg->id != mob_id) {
		mg = pw_avl_get_next(g_mirages_per_mob, mg);
	}

	if (mg) {
		int count = mg->min + round(rand_uniform() * (mg->max - mg->min));
		int i;
		float *pos;
		void *world;

		assert(count <= 32);

		for (i = 0; i < count; i++) {
			dropped_items[4 + i] = MIRAGE_CELESTONE_ID;
		}

		dropped_items[0] = team_id;
		dropped_items[1] = team_seq;
		dropped_items[2] = mob_id;
		dropped_items[3] = count;

		pos = (float *)(*(int *)(gnpc_imp + 8) + 0x20);
		world = *(void **)(gnpc_imp + 4);

		MSG(msg);
		build_message(msg, 0x53, get_server_xid(), killer_xid, pos, 0, dropped_items, (count + 4) * sizeof(int));
		post_lazy_message(world, msg);
	}

	

	return org_gnpc_imp_drop_item_from_global_fn(gnpc_imp, killer_xid, player_lvl, team_id, team_seq, wallow_level);
}

static uintptr_t
hooked_pile_items_on_move(void)
{
	register struct pw_item *_src asm ("eax");
	register struct pw_item *_dst asm ("edx");
	/* we force src and dst into the stack this way */
	struct pw_item *src = _src, *dst = _dst;

	if (src->type == dst->type && src->proc_type == dst->proc_type) {
		return 0x808b948;
	} else {
		return 0x808b95d;
	}
}

static uintptr_t
hooked_pile_items(void)
{
	struct pw_item *src, *dst;

	__asm__ (
		"push dword ptr [edx + 0xc];"
		"mov %0, dword ptr [edx - 0x10];"
		"mov %1, dword ptr [esp];"
		"add esp, 4;"
		: "=r"(src), "=r"(dst));

	if (src->type == dst->type && src->proc_type == dst->proc_type) {
		return 0x80b861a;
	} else {
		return 0x80b8704;
	}
}


static void
hook_mirage_boss_drops(void)
{
	char *buf;
	size_t buflen;
	int i, rc;
	struct cjson *cjson;

	g_mirages_per_mob = pw_avl_init(sizeof(struct mirages_per_mob));
	if (!g_mirages_per_mob) {
		fprintf(stderr, "pw_avl_init() failed\n");
		return;
	}

	rc = readfile("boss_drops.json", &buf, &buflen);
	if (rc != 0) {
		fprintf(stderr, "Failed to read boss drops: %d\n", -rc);
		return;
	}

	cjson = cjson_parse(buf);
	if (!cjson) {
		fprintf(stderr, "cjson_parse() failed\n");
		free(buf);
		return;
	}

	for (i = 0; i < cjson->count; i++) {
		struct cjson *drop = JS(cjson, i);
		struct mirages_per_mob *map;
		int id;

		map = pw_avl_alloc(g_mirages_per_mob);
		if (!map) {
			fprintf(stderr, "pw_avl_alloc() failed\n");
			/* TODO cleanup */
			return;
		}

		id = JSi(drop, "id");
		map->id = id;
		map->min = JSi(drop, "min");
		map->max = JSi(drop, "max");
		pw_avl_insert(g_mirages_per_mob, id, map);
	}

	patch_jmp32(0x80a2435, (uintptr_t)hooked_gnpc_imp_drop_item_from_global_fn);
}

static void __stdcall
hooked_on_banish(int role_id)
{
	char tmp[1024];

	snprintf(tmp, sizeof(tmp), "/bin/bash /home/pw/gamed/banish.sh %d", role_id);
	system(tmp);
}

static uint32_t g_libtask_off;
static int
dl_phdr_cb(struct dl_phdr_info *info, size_t size, void *ctx)
{
	if (strstr(info->dlpi_name, "libtask.so") != NULL) {
		g_libtask_off = info->dlpi_addr - 0x10000;
	}
	return 0;
}

static int g_clear_quest_children_depth;
static void __stdcall
hooked_clear_quest_required_item(void **_real_fn, void *this, int item_id, int count)
{
	void __cdecl (*real_fn)(void *this, int item_id, int count) = *_real_fn;

	if (g_clear_quest_children_depth == 0) {
		fprintf(stderr, "Removing %d x %d\n", item_id, count);
		real_fn(this, item_id, count);
	} else {
		fprintf(stderr, "Not Removing %d x %d\n", item_id, count);
	}
}

static void __cdecl (*org_clear_quest_children)(void *unk1, void *unk2, void *unk3);
static void __cdecl
hooked_clear_quest_children(void *unk1, void *unk2, void *unk3)
{
	g_clear_quest_children_depth++;
	org_clear_quest_children(unk1, unk2, unk3);
	g_clear_quest_children_depth--;
}

extern char **environ;

static void
unset_preload(void)
{
	int i;
	for (i = 0; environ[i]; i++) {
		if (strstr(environ[i],"LD_PRELOAD="))
		{
			environ[i][0] = 'D';
		}
	}
}

static void __attribute__((constructor))
init(void)
{
	/* don't hook into children */
	unset_preload();

	/* don't forbid logging characters wth too many stats */
	patch_mem(0x81398bc, "\x31\xc0\x40\x90", 4);

	/* dont reject movement packets with time < 200 */
	patch_mem(0x807b5e7, "\x00", 1);
	/* patch min stop_move time to 32 */
	patch_mem(0x80baeab, "\x31", 1);
	patch_mem(0x80baeb7, "\x31", 1);

	/* dont reject movement packets with time > 1000, bump the limit to 2000 */
	patch_mem(0x807b5f0, "\xd0\x07", 2);

	/* decrease the pet summon time */
	patch_mem(0x807e5cb, "\x05", 1);
	/* decrease the pet un-summon time */
	patch_mem(0x807e6fc, "\x05", 1);

	/* shorten movement processing, so that other actions are available faster
	 * (originally the server won't make you cast a skill, until movement processing
	 * is done and all players around you see you at your real location) */
	patch_mem(0x80bad6d, "\x66\x90", 2);
	patch_mem(0x80bad72, "\x01\x00\x00\x00", 4);

	/* decrease action delay after player movement */
	patch_mem(0x80bb027, "\xeb", 1);
	patch_mem(0x80bb01a, "\x66\x90", 2);
	patch_mem(0x80bb01f, "\x01", 1);

	/* don't stack items with different proc_type */
	void *tmp = calloc(1, 0x1000);
	assert(tmp);
	memcpy(tmp, "\xe8\x00\x00\x00\x00\xff\xe0", 7);
	u32_to_str(tmp + 1, (uintptr_t)hooked_pile_items_on_move - (uintptr_t)tmp - 5);
	patch_mem(0x808b942, "\xe9\x00\x00\x00\x00\x90", 6);
	patch_jmp32(0x808b942, (uintptr_t)tmp);

	/* ^ on pickup */
	patch_mem(0x80b7aaa, "\x67\x50", 2); /* mov eax instead of [eax] (id) */
	patch_mem(0x80b7d29, "\x67\x50", 2);
	patch_mem(0x80b85d8, "\x66\x90", 2);
	patch_mem(0x80b85dd, "\x83\x3c\x20\xff", 4);
	patch_mem(0x80b860e, "\x8b\xd5", 2); /* mov edx, ebp */
	patch_mem(0x80b8610, "\xe8\x00\x00\x00\x00\xff\xe0\x90\x90\x90", 10);
	patch_jmp32(0x80b8610, (uintptr_t)hooked_pile_items);

	/* send items' proc_type directly to the client */
	//patch_mem(0x8091018, "\x8b\x40\x10", 3);
	//patch_mem(0x809101b, "\x90\x90\x90\x90\x90", 5);
	//patch_mem(0x8091022, "\x08", 1);
	patch_mem(0x8096dd9, "\x8b\x45\x08\xc9\xc3", 5); /* mov eax,param1; leave; ret */

	/* boost skill casting */
	patch_mem(0x80bbd04, "\x01", 1);
	//patch_mem(0x80bb7bf, "\x06", 1);
	//patch_mem(0x80bb9ea, "\x06", 1);
	//patch_mem(0x80bbbd3, "\x06", 1);

	/* boost normal atk */
	patch_mem(0x80bb224, "\x7c", 1);
	patch_mem(0x80bb223, "\x02", 1);
	patch_mem(0x80bb226, "\x83\xe8\x01", 3); /* atk time (EAX) -= 1 */
	patch_mem(0x80bb229, "\x89\x45\xf0", 3); /* store it */
	patch_mem(0x80bb22c, "\xeb\x1f", 2); /* skip the rest of overritten code (assert) */

	patch_mem(0x80bb36b, "\x7c", 1);
	patch_mem(0x80bb36a, "\x02", 1);
	patch_mem(0x80bb36d, "\x83\xe8\x01", 3); /* atk time (EAX) -= 1 */
	patch_mem(0x80bb370, "\x89\x45\xd0", 3); /* store it */
	patch_mem(0x80bb373, "\xeb\x1f", 2); /* skip the rest of overritten code (assert) */

	/* kick instead of banish */
	patch_mem(0x80e3f0a, "\x89\xc7", 2); /* save player id from EAX EDI */
	patch_mem(0x80e3f0c, "\xe8\xe7\x0f\x42\x00", 5); /* move GLog call */
	patch_mem(0x80e3f11, "\x83\xc4\x08\x90", 4);
	patch_mem(0x80e3ee5, "\x4c\x1d", 2); /* increase load limit 10x */
	patch_mem(0x80e3f15, "\xff\x77\x30", 3);
	patch_mem(0x80e3f18, "\xe8", 1);
	patch_jmp32(0x80e3f18, (uintptr_t)hooked_on_banish);
	patch_mem(0x80e3f1d, "\x83\xc4\x08", 3);
	patch_mem(0x80e3f20, "\xeb\x07", 2);

	/* add expiration time to items */
	trampoline_fn((void **)&org_generate_item_for_drop_fn, 6, generate_item_for_drop);
	trampoline_fn((void **)&org_generate_item_from_player_fn, 6, generate_item_from_player);

	/* bump max run speed */
	patch_mem(0x809790a, "\x00\x00\xb4\x41", 4);
	patch_mem(0x85111f8, "\x00\x00\xb4\x41", 4);

	/* bump max movement speed (orig 20, it warps you if you move faster) */
	patch_mem(0x8510660, "\xd7\x83\x47\x44", 4);

	/* don't require teles to use WC */
	patch_mem(0x8080f44, "\xe9\x83\x00\x00\x00", 5);

	/* libtask hooking */
	dl_iterate_phdr(dl_phdr_cb, NULL);

	/* don't remove items-to-acquire for quests you don't complete directly
	 * - e.g. when there's a choice to complete just one of multiple */
	patch_mem(g_libtask_off + 0x209e6, "\x52\xe8\x00\x00\x00\x00\x58", 7);
	patch_jmp32(g_libtask_off + 0x209e6 + 1, (uintptr_t)hooked_clear_quest_required_item);
	org_clear_quest_children = (void *)(g_libtask_off + 0x1f124);
	trampoline_fn((void **)&org_clear_quest_children, 7, hooked_clear_quest_children);

	hook_mirage_boss_drops();

	fprintf(stderr, "gs_preload done\n");
}
