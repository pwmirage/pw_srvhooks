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

#define PAGE_SIZE 4096

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

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

	/* add expiration time to items */
	trampoline_fn((void **)&org_generate_item_for_drop_fn, 6, generate_item_for_drop);
	trampoline_fn((void **)&org_generate_item_from_player_fn, 6, generate_item_from_player);

	fprintf(stderr, "gs_preload done\n");
}
