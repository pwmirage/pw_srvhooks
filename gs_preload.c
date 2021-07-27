/* SPDX-License-Identifier: MIT
 * Copyright(c) 2021 Darek Stojaczyk for pwmirage.com
 */

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

static void __attribute__((constructor))
init(void)
{
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

	/* boost skill casting */
	patch_mem(0x80bbd04, "\x01", 1);
	patch_mem(0x80bb7bf, "\x06", 1);
	patch_mem(0x80bb9ea, "\x06", 1);
	patch_mem(0x80bbbd3, "\x06", 1);

	/* boost normal atk */
	patch_mem(0x80bb224, "\x7c", 1);
	patch_mem(0x80bb223, "\x06", 1);
	patch_mem(0x80bb226, "\x83\xe8\x05", 3); /* atk time (EAX) -= 5 */
	patch_mem(0x80bb229, "\x89\x45\xf0", 3); /* store it */
	patch_mem(0x80bb22c, "\xeb\x1f", 2); /* skip the rest of overritten code (assert) */

	patch_mem(0x80bb36b, "\x7c", 1);
	patch_mem(0x80bb36a, "\x06", 1);
	patch_mem(0x80bb36d, "\x83\xe8\x05", 3); /* atk time (EAX) -= 5 */
	patch_mem(0x80bb370, "\x89\x45\xd0", 3); /* store it */
	patch_mem(0x80bb373, "\xeb\x1f", 2); /* skip the rest of overritten code (assert) */

	/* kick instead of banish */
	patch_mem(0x80e3f0a, "\x89\xc7", 2); /* save player id from EAX EDI */
	patch_mem(0x80e3f0c, "\xe8\xe7\x0f\x42\x00", 5); /* move GLog call */
	patch_mem(0x80e3f11, "\x83\xc4\x08\x90", 4);
	patch_mem(0x80e3ee4, "\xe8\x03", 2); /* increase load limit 2x */
	patch_mem(0x80e3f15, "\xff\x77\x30", 3);
	patch_mem(0x80e3f18, "\xe8", 1);
	patch_jmp32(0x80e3f18, hooked_on_banish);
	patch_mem(0x80e3f1d, "\x83\xc4\x08", 3);
	patch_mem(0x80e3f20, "\xeb\x07", 2);

	/* add expiration time to items */
	trampoline_fn((void **)&org_generate_item_for_drop_fn, 6, generate_item_for_drop);
	trampoline_fn((void **)&org_generate_item_from_player_fn, 6, generate_item_from_player);

	hook_mirage_boss_drops();

	fprintf(stderr, "gs_preload done\n");
}
