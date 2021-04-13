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
		snprintf(tmp + tmplen, MAX(0, sizeof(tmp) - tmplen), "0x%x ", (unsigned char)buf[i]);
	}
	fprintf(stderr, "patching %d bytes at 0x%x: %s", num_bytes, addr, tmp);

	mprotect(page, mprot_bytes, PROT_READ | PROT_WRITE);
	memcpy((void *)addr, buf, num_bytes);
	mprotect(page, mprot_bytes, PROT_READ | PROT_EXEC);
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

	fprintf(stderr, "gs_preload done\n");
}
