/* SPDX-License-Identifier: MIT
 * Copyright(c) 2019-2020 Darek Stojaczyk for pwmirage.com
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>
#include <wchar.h>
#include <locale.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <assert.h>
#include <errno.h>

#include "common.h"
#include "cjson.h"

int g_pwlog_level = 99;
FILE *g_nullfile;
const char g_zeroes[4096];
int g_idmap_can_set;

#ifndef NO_NETWORKING
#ifdef __MINGW32__
#include <wininet.h>

static int
download_wininet(const char *url, const char *filename)
{
	HINTERNET hInternetSession;
	HINTERNET hURL;
	BOOL success;
	DWORD num_bytes = 1;
	FILE *fp;
	DWORD flags;

	DeleteUrlCacheEntry(url);

	fp = fopen(filename, "wb");
	if (!fp) {
		return -errno;
	}

	hInternetSession = InternetOpen("Mirage Patcher", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	if (!hInternetSession) {
		fclose(fp);
		return -1;
	}

	flags = INTERNET_FLAG_DONT_CACHE | INTERNET_FLAG_PRAGMA_NOCACHE | INTERNET_FLAG_NO_CACHE_WRITE;
	hURL = InternetOpenUrl(hInternetSession, url, NULL, 0, flags, 0);
	if (!hURL) {
		InternetCloseHandle(hInternetSession);
		fclose(fp);
		return -1;
	}

	char buf[1024];

	while (num_bytes > 0) {
		success = InternetReadFile(hURL, buf, (DWORD)sizeof(buf), &num_bytes);
		if (!success) {
			break;
		}
		fwrite(buf, 1, (size_t)num_bytes, fp);
	}

	// Close down connections.
	InternetCloseHandle(hURL);
	InternetCloseHandle(hInternetSession);

	fclose(fp);
	return success ? 0 : -1;
}

#else

static int
download_wget(const char *url, const char *filename)
{
	char buf[2048];
	int rc;

	snprintf(buf, sizeof(buf), "wget --no-check-certificate --no-cache --no-cookies \"%s\" -O \"%s\"", url, filename);
	rc = system(buf);
	if (rc != 0) {
		return rc;
	}

	return 0;
}
#endif
#endif

int
download(const char *url, const char *filename)
{
#ifdef NO_NETWORKING
	return -ENOSYS;
#else
	PWLOG(LOG_DEBUG_1, "Fetching \"%s\" ...\n", url);

#ifdef __MINGW32__
	return download_wininet(url, filename);
#else
	return download_wget(url, filename);
#endif

#endif
}

int
readfile(const char *path, char **buf, size_t *len)
{
	FILE *fp;

	fp = fopen(path, "rb");
	if (!fp) {
		return -1;
	}

	fseek(fp, 0, SEEK_END);
	*len = ftell(fp);

	fseek(fp, 0, SEEK_SET);
	*buf = malloc(*len + 1);
	if (!*buf) {
		return -1;
	}

	fread(*buf, 1, *len, fp);
	(*buf)[*len] = 0;
	fclose(fp);

	return 0;
}

int
download_mem(const char *url, char **buf, size_t *len)
{
	int rc;
	char *tmp_filename = "patcher/tmp";

	rc = download((char *)url, tmp_filename);
	if (rc) {
		return rc;
	}

	rc = readfile(tmp_filename, buf, len);
	unlink(tmp_filename);
	return rc;
}

void
normalize_json_string(char *str, bool use_crlf)
{
	char *read_b = str;
	char *write_b = str;

	while (*read_b) { /* write_b is slacking behind */
		char c = *read_b;

		if (*read_b == '\\' && *(read_b + 1) == 'r') {
			/* skip \r entirely */
			read_b++;
			read_b++;
			continue;
		}

		if (use_crlf) {
			if (*read_b == '\\' && *(read_b + 1) == 'n') {
				/* replace \\ with \r, n with \n */
				*write_b++ = '\r';
				c = '\n';
				read_b++;
			}
		} else {
			if (*read_b == '\\' && *(read_b + 1) == 'n') {
				/* replace first \\ with newline, skip second \\ */
				c = '\n';
				read_b++;
			}
		}

		if (*read_b == '\\' && *(read_b + 1) == '"') {
			/* skip first \\ */
			read_b++;
			c = *read_b;
		}

		if (*read_b == '\\' && *(read_b + 1) == '\\') {
			/* skip second \ in strings */
			read_b++;
		}

		if (!*read_b) {
			break;
		}

		*write_b = c;
		read_b++;
		write_b++;

	}

	*write_b = 0;
}

void
fwsprint(FILE *fp, const uint16_t *buf, int maxlen)
{
	char out[4096] = {};
	char *b = out;

	change_charset("UTF-16LE", "UTF-8", (char *)buf, maxlen * 2, out, sizeof(out));
	while (*b && maxlen--) {
		if (*b == '\\') {
			fputs("\\\\", fp);
		} else if (*b == '"') {
			fputs("\\\"", fp);
		} else if (*b == '\r') {
			/* do nothing */
		} else if (*b == '\t') {
			fputs("\\t", fp);
		} else if (*b == '\n') {
			fputs("\\n", fp);
		} else {
			fputc(*b, fp);
		}
		b++;
	}
}

void
sprint(char *dst, size_t dstsize, const char *src, int srcsize)
{
	change_charset("GB2312", "UTF-8", (char *)src, srcsize, dst, dstsize);
}

void
fsprint(FILE *fp, const char *buf, int maxlen)
{
	char out[1024] = {};
	char *b = out;

	sprint(out, sizeof(out), buf, maxlen);
	while (*b && maxlen--) {
		if (*b == '\\') {
			fputs("\\\\", fp);
		} else {
			fputc(*b, fp);
		}
		b++;
	}
}


void
fwsprintf(FILE *fp, const char *fmt, const uint16_t *buf, int maxlen)
{
	char c;

	while ((c = *fmt++)) {
		if (c == '%' && *fmt == 's') {
			fwsprint(fp, buf, maxlen);
			fmt++;
		} else {
			putc(c, fp);
		}
	}
}

void
wsnprintf(uint16_t *dst, size_t dstsize, const char *src) {
	char c;

	memset(dst, 0, dstsize);
	while (dstsize > 0 && (c = *src++)) {
		if (c == '\n' && dstsize >= 2) {
			*dst++ = '\r';
			*dst++ = '\n';
			dstsize -= 2;
		} else {
			*dst++ = c;
			dstsize--;
		}
	}

	if (dstsize == 0) {
		*(dst - 1) = 0;
	} else {
		*dst = 0;
	}
}

uint32_t
js_strlen(const char *str)
{
	uint32_t len = 0;
	char c;

	while ((c = *str++)) {
		if (c == '\n') {
			len++;
		}
		len++;
	}
	return len;
}

int
pw_version_load(struct pw_version *ver)
{
	FILE *fp = fopen("patcher/version", "rb");

	if (!fp) {
		memset(ver, 0, sizeof(*ver));
		ver->magic = PW_VERSION_MAGIC;
		return errno;
	}

	fread(ver, 1, sizeof(*ver), fp);
	ver->branch[sizeof(ver->branch) - 1] = 0;
	fclose(fp);

	if (ver->magic != PW_VERSION_MAGIC) {
		memset(ver, 0, sizeof(*ver));
		ver->magic = PW_VERSION_MAGIC;
		return 1;
	}

	return 0;
}

int
pw_version_save(struct pw_version *ver)
{
	FILE *fp = fopen("patcher/version", "wb");

	if (!fp) {
		return -errno;
	}

	fwrite(ver, 1, sizeof(*ver), fp);
	ver->branch[sizeof(ver->branch) - 1] = 0;
	fclose(fp);

	return 0;
}

void
pwlog(int type, const char *filename, unsigned lineno, const char *fnname, const char *fmt, ...)
{
	va_list args;
	const char *type_str;

	if (type > g_pwlog_level) {
		return;
	}

	switch (type) {
		case LOG_ERROR:
			type_str = "ERROR";
			break;
		case LOG_INFO:
			type_str = "INFO";
			break;
		case LOG_DEBUG:
			type_str = "DEBUG";
			break;
		case LOG_DEBUG_1:
			type_str = "DEBUG1";
			break;
		case LOG_DEBUG_5:
			type_str = "DEBUG5";
			break;
		default:
			return;
	}
	
	fprintf(stderr, "%s:%u %s(): %s: ", filename, lineno, fnname, type_str);

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	fflush(stderr);
}

static void __attribute__((constructor))
common_init()
{
	g_nullfile = fopen("/dev/null", "w");
	if (g_nullfile == NULL) {
		g_nullfile = fopen("NUL", "w");
	}
}
