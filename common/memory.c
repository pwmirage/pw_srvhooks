/* SPDX-License-Identifier: MIT
 * Copyright(c) 2020-2022 Darek Stojaczyk for pwmirage.com
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

#define MessageBox(...)

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif



struct mem_region_4kb {
	char data[4096];
	/* which bytes were overwritten */
	bool byte_mask[4096];
};

struct mem_region_1mb {
	struct mem_region_4kb *pages[256];
};

struct mem_region_1mb *g_mem_map[4096];

enum patch_mem_type {
	PATCH_MEM_T_RAW,
	PATCH_MEM_T_TRAMPOLINE,
	PATCH_MEM_T_TRAMPOLINE_FN
};

struct patch_mem_t {
	enum patch_mem_type type;
    uintptr_t addr;
    int replaced_bytes;
    char asm_code[0x1000];
	struct patch_mem_t *next;
};

static struct patch_mem_t *g_static_patches;

static void *
mem_alloc(int size)
{
#ifdef __MINGW32__
	return VirtualAlloc(NULL, (size + 0xFFF) & ~0xFFF, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#else
	return calloc(1, (size + 0xFFF) & ~0xFFF);
#endif
}

static void
mem_free(void *mem, int size)
{
#ifdef __MINGW32__
	VirtualFree(mem, size, MEM_RELEASE);
#else
	return free(mem);
#endif
}

static int
mem_protect(void *mem, int size, bool rw)
{
#ifdef __MINGW32__
	DWORD prevProt;
	/* FIXME */
	VirtualProtect((void *)addr, num_bytes, PAGE_EXECUTE_READWRITE, &prevProt);
#else
	void *mem_aligned = (void *)((uintptr_t)mem & ~0xFFF);

	return mprotect(mem_aligned, (mem - mem_aligned + size + 0xFFF) & ~0xFFF, PROT_READ | (rw ? PROT_WRITE : PROT_EXEC));
#endif

}

void
_patch_mem_unsafe(uintptr_t addr, const char *buf, unsigned num_bytes)
{
	mem_protect((void *)addr, num_bytes, true);
	memcpy((void *)addr, buf, num_bytes);
	mem_protect((void *)addr, num_bytes, false);
}

void
_patch_mem_u32_unsafe(uintptr_t addr, uint32_t u32)
{
	union {
		char c[4];
		uint32_t u;
	} u;

	u.u = u32;
	_patch_mem_unsafe(addr, u.c, 4);
}

void
_patch_jmp32_unsafe(uintptr_t addr, uintptr_t fn)
{
	_patch_mem_u32_unsafe(addr + 1, fn - addr - 5);
}

static void
backup_page_mem(uintptr_t addr, unsigned len)
{
	uintptr_t addr_4k = addr / 4096;
	uintptr_t addr_1mb = addr_4k / 256;
	uintptr_t offset_4k = addr_4k % 256;
	struct mem_region_1mb *reg_1m = g_mem_map[addr_1mb];
	struct mem_region_4kb *reg_4k;
	unsigned i;

	if (!reg_1m) {
		reg_1m = g_mem_map[addr_1mb] = calloc(1, sizeof(*reg_1m));
		if (!reg_1m) {
			assert(false);
			return;
		}
	}

	reg_4k = reg_1m->pages[offset_4k];
	if (!reg_4k) {
		reg_4k = reg_1m->pages[offset_4k] = calloc(1, sizeof(*reg_4k));
		if (!reg_4k) {
			assert(false);
			return;
		}

		memcpy(reg_4k->data, (void *)(addr_4k * 4096), 4096);
	}

	for (i = 0; i < len && i < 4096; i++) {
		reg_4k->byte_mask[addr % 4096 + i] = 1;
	}
}

static void
backup_mem(uintptr_t addr, unsigned num_bytes)
{
	unsigned u;

	for (u = 0; u < (num_bytes + 4095) / 4096; u++) {
		unsigned page_bytes = MIN(num_bytes, 4096 - (addr % 4096));
		backup_page_mem(addr, page_bytes);
		addr += page_bytes;
	}
}

void
patch_mem(uintptr_t addr, const char *buf, unsigned num_bytes)
{
	backup_mem(addr, num_bytes);
	mem_protect((void *)addr, num_bytes, true);
	memcpy((void *)addr, buf, num_bytes);
	mem_protect((void *)addr, num_bytes, false);
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
patch_mem_u16(uintptr_t addr, uint16_t u16)
{
	union {
		char c[2];
		uint32_t u;
	} u;

	u.u = u16;
	patch_mem(addr, u.c, 2);
}

void
patch_jmp32(uintptr_t addr, uintptr_t fn)
{
	uint8_t op = *(char *)addr;
	if (op != 0xe9 && op != 0xe8) {
		assert(false && "patch_jmp32() on invalid JMP/CALL");
		return;
	}

	patch_mem_u32(addr + 1, fn - addr - 5);
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

static char g_nops[64];

static void __attribute__((constructor (120) ))
init_nops(void)
{
	memset(g_nops, 0x90, sizeof(g_nops));
}

void
trampoline_call(uintptr_t addr, unsigned replaced_bytes, void *fn)
{
	char buf[32];
	char *code;

	assert(replaced_bytes >= 5 && replaced_bytes <= 64);
	code = mem_alloc(14 + replaced_bytes);
	if (code == NULL) {
		MessageBox(NULL, "malloc failed", "Status", MB_OK);
		return;
	}

	/* prepare the code to jump to */
	code[0] = 0x60; /* pushad */
	code[1] = 0x9c; /* pushfd */
	code[2] = 0xe8; /* call */
	u32_to_str(code + 3, (uintptr_t)fn - (uintptr_t)code - 2 - 5); /* fn rel addr */
	code[7] = 0x9d; /* popfd */
	code[8] = 0x61; /* popad */
	memcpy(code + 9, (void *)addr, replaced_bytes); /* replaced instructions */
	code[9 + replaced_bytes] = 0xe9; /* jmp */
	u32_to_str(code + 10 + replaced_bytes, /* jump back rel addr */
			addr + replaced_bytes - ((uintptr_t)code + 9 + replaced_bytes) - 5);

	mem_protect(code, 14 + replaced_bytes, false);

	/* jump to new code */
	buf[0] = 0xe9;
	u32_to_str(buf + 1, (uintptr_t)code - addr - 5);
	memset(buf + 5, 0x90, replaced_bytes - 5);
	patch_mem(addr, buf, replaced_bytes);
}

void *
trampoline_buf(uintptr_t addr, unsigned replaced_bytes, const char *buf, unsigned num_bytes)
{
	char tmpbuf[32];
	char *code;

	assert(replaced_bytes >= 5 && replaced_bytes <= 64);
	code = mem_alloc(9 + num_bytes + replaced_bytes);
	if (code == NULL) {
		MessageBox(NULL, "malloc failed", "Status", MB_OK);
		return NULL;
	}

	/* prepare the code to jump to */
	code[0] = 0x60; /* pushad */
	code[1] = 0x9c; /* pushfd */
	memcpy(code + 2, buf, num_bytes);
	code[2 + num_bytes] = 0x9d; /* popfd */
	code[3 + num_bytes] = 0x61; /* popad */
	memcpy(code + 4 + num_bytes, (void *)addr, replaced_bytes); /* replaced instructions */
	code[4 + num_bytes + replaced_bytes] = 0xe9; /* jmp */
	u32_to_str(code + 5 + num_bytes + replaced_bytes, /* jump back rel addr */
			addr + replaced_bytes - ((uintptr_t)code + 4 + num_bytes + replaced_bytes) - 5);

	mem_protect(code, 14 + replaced_bytes, false);

	/* jump to new code */
	tmpbuf[0] = 0xe9;
	u32_to_str(tmpbuf + 1, (uintptr_t)code - addr - 5);
	memset(tmpbuf + 5, 0x90, replaced_bytes - 5);
	patch_mem(addr, tmpbuf, replaced_bytes);

	return code + 2;
}

void
trampoline_fn(void **orig_fn, unsigned replaced_bytes, void *fn)
{
	uint32_t addr = (uintptr_t)*orig_fn;
	char orig_code[32];
	char buf[32];
	char *orig;

	memcpy(orig_code, (void *)addr, replaced_bytes);

	orig = mem_alloc(replaced_bytes + 5);
	if (orig == NULL) {
		MessageBox(NULL, "malloc failed", "Status", MB_OK);
		return;
	}

	/* copy original code to a buffer */
	memcpy(orig, (void *)addr, replaced_bytes);
	/* follow it by a jump to the rest of original code */
	orig[replaced_bytes] = 0xe9;
	u32_to_str(orig + replaced_bytes + 1, (uint32_t)(uintptr_t)addr + replaced_bytes - (uintptr_t)orig - replaced_bytes - 5);

	mem_protect(orig, replaced_bytes + 5, false);

	/* patch the original code to do a jump */
	buf[0] = 0xe9;
	u32_to_str(buf + 1, (uint32_t)(uintptr_t)fn - addr - 5);
	memset(buf + 5, 0x90, replaced_bytes - 5);
	patch_mem(addr, buf, replaced_bytes);

	*orig_fn = orig;
}

void
trampoline_winapi_fn(void **orig_fn, void *fn)
{
	uint32_t addr = (uintptr_t)*orig_fn;
	char buf[7];

	buf[0] = 0xe9; /* jmp */
	u32_to_str(buf + 1, (uint32_t)(uintptr_t)fn - addr);
	buf[5] = 0xeb; /* short jump */
	buf[6] = 0xf9; /* 7 bytes before */

	/* override 5 preceeding bytes (nulls) and 2 leading bytes */
	patch_mem(addr - 5, buf, 7);
	*orig_fn += 2;
}

static int
assemble_trampoline(uintptr_t addr, int replaced_bytes,
		char *asm_buf, unsigned char **out)
{
	unsigned char *code, *c;
	unsigned char *tmpcode;
	int len;

	assert(replaced_bytes >= 5 && replaced_bytes <= 64);
	code = c = mem_alloc(0x1000);
	if (code == NULL) {
		return -ENOMEM;
	}

	char *asm_org = strstr(asm_buf, TRAMPOLINE_ORG);
	if (asm_org != NULL &&
			(*(asm_org + sizeof(TRAMPOLINE_ORG) - 1) == ';' ||
			 *(asm_org + sizeof(TRAMPOLINE_ORG) - 1) == 0)) {
		/* First assemble everything before the org, then copy org, and finally
		 * assemble the rest  */
		asm_org[0] = 0;
		len = assemble_x86((uintptr_t)c, asm_buf, &tmpcode);
		if (len < 0) {
			mem_free(code, 0x1000);
			return len;
		}

		if (len > 0) {
			memcpy(c, tmpcode, len);
			c += len;
		}

		memcpy(c, (void *)addr, replaced_bytes); /* replaced instructions */
		c += replaced_bytes;

		asm_buf = asm_org + strlen(TRAMPOLINE_ORG);
	}

	len = assemble_x86((uintptr_t)c, asm_buf, &tmpcode);
	if (len < 0) {
		mem_free(code, 0x1000);
		return len;
	}

	memcpy(c, tmpcode, len);
	c += len;

	*c++ = 0xe9; /* jmp */
	u32_to_str((char *)c, /* jump back rel addr */
			addr + replaced_bytes - ((uintptr_t)c - 1) - 5);
	c += 4;

	mem_protect(code, 0x1000, false);
	*out = code;
	return c - code;
}

void
trampoline_fn_static_add(void **orig_fn, int replaced_bytes, void *fn)
{
	struct patch_mem_t *t;

	assert(replaced_bytes >= 5 && replaced_bytes <= 64);
	t = calloc(1, sizeof(*t));
	if (!t) {
		MessageBox(NULL, "malloc failed", "Status", MB_OK);
		assert(false);
		return;
	}

	t->type = PATCH_MEM_T_TRAMPOLINE_FN;
	t->addr = (uintptr_t)(void *)orig_fn;
	t->replaced_bytes = replaced_bytes;
	*(void **)t->asm_code = fn;

	t->next = g_static_patches;
	g_static_patches = t;
}

void
trampoline_static_add(uintptr_t addr, int replaced_bytes, const char *asm_fmt, ...)
{
	struct patch_mem_t *t;
	va_list args;
	char *c;

	assert(replaced_bytes >= 5 && replaced_bytes <= 64);
	t = calloc(1, sizeof(*t));
	if (!t) {
		MessageBox(NULL, "malloc failed", "Status", MB_OK);
		assert(false);
		return;
	}

	t->type = PATCH_MEM_T_TRAMPOLINE;
	t->addr = addr;
	t->replaced_bytes = replaced_bytes;

	va_start(args, asm_fmt);
	vsnprintf(t->asm_code, sizeof(t->asm_code), asm_fmt, args);
	va_end(args);

	c = t->asm_code;
	while (*c) {
		if (*c == '\t') {
			*c = ' ';
		}
		c++;
	}

	t->next = g_static_patches;
	g_static_patches = t;
}

void
patch_mem_static_add(uintptr_t addr, int replaced_bytes, const char *asm_fmt, ...)
{
	struct patch_mem_t *t;
	va_list args;
	char *c;

	t = calloc(1, sizeof(*t));
	if (!t) {
		MessageBox(NULL, "malloc failed", "Status", MB_OK);
		assert(false);
		return;
	}

	t->type = PATCH_MEM_T_RAW;
	t->addr = addr;
	t->replaced_bytes = replaced_bytes;

	va_start(args, asm_fmt);
	vsnprintf(t->asm_code, sizeof(t->asm_code), asm_fmt, args);
	va_end(args);

	c = t->asm_code;
	while (*c) {
		if (*c == '\t') {
			*c = ' ';
		}
		c++;
	}

	t->next = g_static_patches;
	g_static_patches = t;
}

static void
process_static_patch_mem(struct patch_mem_t *p)
{
	char tmp[0x1000];
	unsigned char *code;
	int len = 0;

	fprintf(stderr, "patching at 0x%x\n", p->addr);

	switch(p->type) {
	case PATCH_MEM_T_RAW: {
		len = assemble_x86(p->addr, p->asm_code, &code);
		if (len < 0) {
			fprintf(stderr, "patching %d bytes at 0x%x: can't assemble, invalid instruction", len, p->addr);
			return;
		}

		if (len > p->replaced_bytes) {
			fprintf(stderr, "patching %d bytes at 0x%x: assembled code takes %d bytes and doesn't fit (max %d)", len, p->addr, len, p->replaced_bytes);
			return;
		}

		memcpy(tmp, code, len);
		if (len < p->replaced_bytes) {
			memset(tmp + len, 0x90, p->replaced_bytes - len);
		}
		patch_mem(p->addr, tmp, p->replaced_bytes);
		break;
	}
	case PATCH_MEM_T_TRAMPOLINE: {
		len = assemble_trampoline(p->addr, p->replaced_bytes, p->asm_code, &code);

		/* jump to new code */
		tmp[0] = 0xe9;
		u32_to_str(tmp + 1, (uintptr_t)code - p->addr - 5);
		memset(tmp + 5, 0x90, p->replaced_bytes - 5);
		patch_mem(p->addr, tmp, p->replaced_bytes);
		break;
	}
	case PATCH_MEM_T_TRAMPOLINE_FN: {
		trampoline_fn((void **)p->addr, p->replaced_bytes, *(void **)p->asm_code);
		break;
	}
	}
}

void
patch_mem_static_init(void)
{
	struct patch_mem_t *p = g_static_patches;

	while (p) {
		process_static_patch_mem(p);
		free(p);
		p = p->next;
	}
}

void
restore_mem(void)
{
	struct mem_region_4kb *reg_4k;
	struct mem_region_1mb *reg_1m;
	unsigned i, j, b;
	void *addr;

	for (i = 0; i < 4096; i++) {
		reg_1m = g_mem_map[i];
		if (!reg_1m) {
			continue;
		}

		for (j = 0; j < 256; j++) {
			reg_4k = reg_1m->pages[j];
			if (!reg_4k) {
				continue;
			}

			addr = (void *)(uintptr_t)(i * 1024 * 1024 + j * 4096);
			mem_protect(addr, 4096, true);
			for (b = 0; b < 4096; b++) {
				if (reg_4k->byte_mask[b]) {
					*(char *)(addr + b) = *(char *)(reg_4k->data + b);
				}
			}
			mem_protect(addr, 4096, false);
		}
	}
}

int
split_string_to_words(char *input, char split_by, char **argv, int *argc)
{
    char *c, *start;
	int cur_argc = 0;
    int rc = 0;

    #define NEW_WORD() \
    ({ \
        *c = 0; \
		if (*start) { \
			argv[cur_argc++] = start; \
			if (cur_argc == *argc) { \
				break; \
			} \
		} \
        start = c + 1; \
    })

    c = start = input;
    while (*c) {
        if (*c == split_by) {
            NEW_WORD();
        }
        c++;
    }

    if (*c == 0) {
        do {
            NEW_WORD();
        } while (0);
    }

	#undef NEW_WORD

	*argc = cur_argc;
    return rc;
}

const char *g_regs[] = {
	"eax",
	"ecx",
	"edx",
	"ebx",
	"esp",
	"ebp",
	"esi",
	"edi",
};

static char
get_reg_idx(const char *name)
{
	int i;

	for (i = 0; i < sizeof(g_regs) / sizeof(g_regs[0]); i++) {
		if (strcmp(g_regs[i], name) == 0) {
			return i;
		}
	}

	assert(false);
	return -1;
}

int
assemble_x86(uint32_t addr, char *in, unsigned char **out)
{
	static unsigned char outbuf[128];
	unsigned char *o = outbuf;
	char *instruction_arr[32];
	int instruction_cnt = sizeof(instruction_arr) / sizeof(instruction_arr[0]);
	int i, rc;

	rc = split_string_to_words(in, ';', instruction_arr, &instruction_cnt);
	if (rc != 0) {
		return rc;
	}

	for (i = 0; i < instruction_cnt; i++) {
		char *ins_s = instruction_arr[i];
		char *parts[3] = {};
		int opcount = 3;
		char *ins, *op1, *op2;

		rc = split_string_to_words(ins_s, ' ', parts, &opcount);
		if (rc != 0 || opcount == 0) {
			continue;
		}

		ins = parts[0];
		op1 = parts[1];
		op2 = parts[2];

		if (strcmp(ins, "push") == 0) {
			assert(opcount == 2);
			*o++ = (unsigned char)(0x50 + get_reg_idx(op1));
			addr++;
		} else if (strcmp(ins, "call") == 0 || strcmp(ins, "jmp") == 0) {
			union {
				unsigned char c[4];
				uint32_t u;
			} u;

			assert(opcount == 2);
			u.u = strtoll(op1, NULL, 16) - addr - 5;

			if (strcmp(ins, "call") == 0) {
				*o++ = (unsigned char)0xe8;
			} else {
				*o++ = (unsigned char)0xe9;
			}
			*o++ = u.c[0];
			*o++ = u.c[1];
			*o++ = u.c[2];
			*o++ = u.c[3];
			addr += 5;
		}
	}

	*out = outbuf;
	return o - outbuf;
}
