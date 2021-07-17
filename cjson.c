#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "cjson_ext.h"
#include "common.h"

static struct cjson g_null_json = {};

struct cjson_mempool {
	struct cjson_mempool *next;
	unsigned count;
	unsigned capacity;
	struct cjson obj[0];
};

static struct cjson *
new_obj(struct cjson_mempool **mem_p)
{
	struct cjson_mempool *mem = *mem_p;
	size_t num_items = mem->capacity * 2;

	if (mem->count < mem->capacity) {
		return &mem->obj[mem->count++];
	}

	mem = calloc(1, sizeof(*mem) + num_items * sizeof(struct cjson));
	if (!mem) {
		assert(false);
		return NULL;
	}

	mem->capacity = num_items;
	mem->count = 1;

	(*mem_p)->next = mem;
	*mem_p = mem;
	return &mem->obj[0];
}

static void
cjson_clean_mem(struct cjson *json)
{
	struct cjson_mempool *mem = json->mem;
	json->a = NULL;

	while (mem) {
		mem->count = 0;
		memset(mem->obj, 0, mem->capacity * sizeof(*mem->obj));
		mem = mem->next;
	}
}

void
cjson_free(struct cjson *json)
{
	struct cjson_mempool *mem = json->mem;

	while (mem) {
		struct cjson_mempool *next = mem;

		next = mem->next;
		free(mem);
		mem = next;
	}
}

int
cjson_add_child(struct cjson *parent, struct cjson *child)
{
	struct cjson *last = parent->a;

	if (!parent || (parent->type != CJSON_TYPE_OBJECT && parent->type != CJSON_TYPE_ARRAY)) {
		assert(false);
		return -EINVAL;
	}

	if (!last) {
		parent->a = child;
		parent->count++;
		assert(child->next == NULL);
		child->next = NULL;
		return 0;
	}

	while (last->next) last = last->next;
	last->next = child;
	assert(child->next == NULL);
	child->next = NULL;
	parent->count++;
	return 0;
}

struct cjson *
cjson_parse(char *str)
{
	struct cjson_mempool *mem;
	struct cjson *top_obj; 
	struct cjson *cur_obj;
	char *cur_key = NULL;
	char *b = str;
	bool need_comma = false;

	if (*b != '{' && *b != '[') {
		return NULL;
	}

	mem = calloc(1, sizeof(*mem) + CJSON_MIN_POOLSIZE * sizeof(struct cjson));
	if (!mem) {
		assert(false);
		return NULL;
	}
	mem->capacity = CJSON_MIN_POOLSIZE;

	top_obj = cur_obj = new_obj(&mem);
	cur_obj->parent = NULL;
	cur_obj->key = "";
	cur_obj->type = *b == '{' ? CJSON_TYPE_OBJECT : CJSON_TYPE_ARRAY;
	cur_obj->mem = mem;

	/* we handled the root object/array separately, go on */
	b++;

	while (*b) {
		switch(*b) {
			case '[':
			case '{': {
				struct cjson *obj;

				need_comma = false;
				if (!cur_key && cur_obj->type != CJSON_TYPE_ARRAY) {
					assert(false);
					goto err;
				}

				obj = new_obj(&mem);
				if (!obj) {
					assert(false);
					goto err;
				}
				obj->parent = cur_obj;
				obj->key = cur_key;
				obj->type = *b == '{' ? CJSON_TYPE_OBJECT : CJSON_TYPE_ARRAY;
				if (cjson_add_child(cur_obj, obj) != 0) {
					assert(false);
					goto err;
				}
				cur_obj = obj;
				cur_key = NULL;
				break;
			}
			case ']':
			case '}': {
				need_comma = true;
				if (cur_key || (*b == ']' && cur_obj->type == CJSON_TYPE_OBJECT) ||
				    (*b == '}' && cur_obj->type == CJSON_TYPE_ARRAY)) {
					assert(false);
					goto err;
				}

				cur_obj = cur_obj->parent;
				if (!cur_obj) {
					return top_obj;
				}
				break;
			}
			case '"': {
				char *start = ++b;

				while (*b && (*(b - 1) == '\\' || *b != '"')) b++;
				if (*b == 0 || *(b + 1) == 0) {
					goto err;
				}
				*b = 0;

				if (cur_key || cur_obj->type == CJSON_TYPE_ARRAY) {
					struct cjson *obj = new_obj(&mem);

					if (!obj) {
						assert(false);
						goto err;
					}
					obj->parent = cur_obj;
					obj->key = cur_key;
					obj->type = CJSON_TYPE_STRING;
					obj->s = start;
					if (cjson_add_child(cur_obj, obj) != 0) {
						assert(false);
						goto err;
					}

					cur_key = NULL;
					need_comma = true;
				} else {
					if (need_comma) {
						assert(false);
						goto err;
					}

					if (cur_obj->type != CJSON_TYPE_OBJECT) {
						assert(false);
						goto err;
					}

					cur_key = start;
				}
				break;
			}
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
			case '-':
			case '.':
			{
				struct cjson *obj;
				char *end;

				if (!cur_key && cur_obj->type != CJSON_TYPE_ARRAY) {
					assert(false);
					goto err;
				}


				obj = new_obj(&mem);
				if (!obj) {
					assert(false);
					goto err;
				}
				obj->parent = cur_obj;
				obj->key = cur_key;

				errno = 0;
				obj->i = strtoll(b, &end, 0);
				if (end == b || errno == ERANGE) {
					assert(false);
					goto err;
				}

				if (*end == '.' || *end == 'e' || *end == 'E') {
					obj->d = strtod(b, &end);
					if (end == b || errno == ERANGE) {
						assert(false);
						goto err;
					}
					obj->type = CJSON_TYPE_FLOAT;
				} else {
					obj->type = CJSON_TYPE_INTEGER;
				}

				if (cjson_add_child(cur_obj, obj) != 0) {
					assert(false);
					goto err;
				}

				b = end - 1; /* will be incremented */
				cur_key = NULL;
				break;
			}
			case 't':
			case 'f':
			{
				struct cjson *obj;
				bool val;

				/* truexyz will still match as true -> don't care */
				if (strncmp(b, "true", 4) == 0) {
					val = true;
				} else if (strncmp(b, "false", 5) == 0) {
					val = false;
				} else {
					break;
				}

				if (!cur_key && cur_obj->type != CJSON_TYPE_ARRAY) {
					assert(false);
					goto err;
				}

				obj = new_obj(&mem);
				if (!obj) {
					assert(false);
					goto err;
				}
				obj->i = val;
				obj->parent = cur_obj;
				obj->key = cur_key;
				obj->type = CJSON_TYPE_BOOLEAN;

				if (cjson_add_child(cur_obj, obj) != 0) {
					assert(false);
					goto err;
				}

				b += val ? 3 : 4; /* will be incremented */
				cur_key = NULL;
				break;
			}
			case 'n':
			{
				struct cjson *obj;

				/* nullxyz will still match as true -> don't care */
				if (strncmp(b, "null", 4) != 0) {
					break;
				}

				if (!cur_key && cur_obj->type != CJSON_TYPE_ARRAY) {
					assert(false);
					goto err;
				}

				obj = new_obj(&mem);
				if (!obj) {
					assert(false);
					goto err;
				}
				obj->i = 0;
				obj->parent = cur_obj;
				obj->key = cur_key;
				obj->type = CJSON_TYPE_NULL;

				if (cjson_add_child(cur_obj, obj) != 0) {
					assert(false);
					goto err;
				}

				b += 3; /* will be incremented */
				cur_key = NULL;
				break;
			}
			case ',':
				need_comma = false;
				break;
			case ':':
			case ' ':
			default:
				break;
		}
		b++;
	}

	return top_obj;
err:
	cjson_free(top_obj);
	return NULL;
}

int
cjson_parse_arr_stream(char *str, cjson_parse_arr_stream_cb obj_cb, void *cb_ctx)
{
	struct cjson_mempool *mem;
	struct cjson top_obj = {0};
	struct cjson *cur_obj;
	char *cur_key = NULL;
	char *b = str;
	bool need_comma = false;

	if (*b == 0) {
		return 0;
	}

	if (*b != '[') {
		return -EINVAL;
	}

	mem = calloc(1, sizeof(*mem) + CJSON_MIN_POOLSIZE * sizeof(struct cjson));
	if (!mem) {
		assert(false);
		return -ENOMEM;
	}
	mem->capacity = CJSON_MIN_POOLSIZE;

	cur_obj = &top_obj;
	cur_obj->parent = NULL;
	cur_obj->key = "";
	cur_obj->type = CJSON_TYPE_ARRAY;
	cur_obj->mem = mem;

	/* we handled the root object/array separately, go on */
	b++;

	while (*b) {
		switch(*b) {
			case '[':
			case '{': {
				struct cjson *obj;

				need_comma = false;
				if (!cur_key && cur_obj->type != CJSON_TYPE_ARRAY) {
					assert(false);
					goto err;
				}

				obj = new_obj(&mem);
				if (!obj) {
					assert(false);
					goto err;
				}
				obj->parent = cur_obj;
				obj->key = cur_key;
				obj->type = *b == '{' ? CJSON_TYPE_OBJECT : CJSON_TYPE_ARRAY;
				if (cjson_add_child(cur_obj, obj) != 0) {
					assert(false);
					goto err;
				}
				cur_obj = obj;
				cur_key = NULL;
				break;
			}
			case ']':
			case '}': {
				need_comma = true;
				if (cur_key || (*b == ']' && cur_obj->type == CJSON_TYPE_OBJECT) ||
				    (*b == '}' && cur_obj->type == CJSON_TYPE_ARRAY)) {
					assert(false);
					goto err;
				}

				if (cur_obj->parent == &top_obj) {
					obj_cb(cb_ctx, cur_obj);
					cjson_clean_mem(&top_obj);
					cur_obj = &top_obj;
				} else {
					cur_obj = cur_obj->parent;
					if (!cur_obj) {
						goto end;
					}
				}
				break;
			}
			case '"': {
				char *start = ++b;

				while (*b && (*(b - 1) == '\\' || *b != '"')) b++;
				if (*b == 0 || *(b + 1) == 0) {
					goto err;
				}
				*b = 0;

				if (cur_key || cur_obj->type == CJSON_TYPE_ARRAY) {
					struct cjson *obj = new_obj(&mem);

					if (!obj) {
						assert(false);
						goto err;
					}
					obj->parent = cur_obj;
					obj->key = cur_key;
					obj->type = CJSON_TYPE_STRING;
					obj->s = start;
					if (cjson_add_child(cur_obj, obj) != 0) {
						assert(false);
						goto err;
					}

					cur_key = NULL;
					need_comma = true;
				} else {
					if (need_comma) {
						assert(false);
						goto err;
					}

					if (cur_obj->type != CJSON_TYPE_OBJECT) {
						assert(false);
						goto err;
					}

					cur_key = start;
				}
				break;
			}
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
			case '-':
			case '.':
			{
				struct cjson *obj;
				char *end;

				if (!cur_key && cur_obj->type != CJSON_TYPE_ARRAY) {
					assert(false);
					goto err;
				}


				obj = new_obj(&mem);
				if (!obj) {
					assert(false);
					goto err;
				}
				obj->parent = cur_obj;
				obj->key = cur_key;

				errno = 0;
				obj->i = strtoll(b, &end, 0);
				if (end == b || errno == ERANGE) {
					assert(false);
					goto err;
				}

				if (*end == '.' || *end == 'e' || *end == 'E') {
					obj->d = strtod(b, &end);
					if (end == b || errno == ERANGE) {
						assert(false);
						goto err;
					}
					obj->type = CJSON_TYPE_FLOAT;
				} else {
					obj->type = CJSON_TYPE_INTEGER;
				}

				if (cjson_add_child(cur_obj, obj) != 0) {
					assert(false);
					goto err;
				}

				b = end - 1; /* will be incremented */
				cur_key = NULL;
				break;
			}
			case 't':
			case 'f':
			{
				struct cjson *obj;
				bool val;

				/* truexyz will still match as true -> don't care */
				if (strncmp(b, "true", 4) == 0) {
					val = true;
				} else if (strncmp(b, "false", 5) == 0) {
					val = false;
				} else {
					break;
				}

				if (!cur_key && cur_obj->type != CJSON_TYPE_ARRAY) {
					assert(false);
					goto err;
				}

				obj = new_obj(&mem);
				if (!obj) {
					assert(false);
					goto err;
				}
				obj->i = val;
				obj->parent = cur_obj;
				obj->key = cur_key;
				obj->type = CJSON_TYPE_BOOLEAN;

				if (cjson_add_child(cur_obj, obj) != 0) {
					assert(false);
					goto err;
				}

				b += val ? 3 : 4; /* will be incremented */
				cur_key = NULL;
				break;
			}
			case 'n':
			{
				struct cjson *obj;

				/* nullxyz will still match as true -> don't care */
				if (strncmp(b, "null", 4) != 0) {
					break;
				}

				if (!cur_key && cur_obj->type != CJSON_TYPE_ARRAY) {
					assert(false);
					goto err;
				}

				obj = new_obj(&mem);
				if (!obj) {
					assert(false);
					goto err;
				}
				obj->i = 0;
				obj->parent = cur_obj;
				obj->key = cur_key;
				obj->type = CJSON_TYPE_NULL;

				if (cjson_add_child(cur_obj, obj) != 0) {
					assert(false);
					goto err;
				}

				b += 3; /* will be incremented */
				cur_key = NULL;
				break;
			}
			case ',':
				need_comma = false;
				break;
			case ':':
			case ' ':
			default:
				break;
		}
		b++;
	}

end:
	cjson_free(&top_obj);
	return (int)(b - str + 1);
err:
	cjson_free(&top_obj);
	return -EFAULT;
}

struct cjson *
cjson_obj(struct cjson *json, const char *key)
{
	struct cjson *entry = json->a;

	if (json->type == CJSON_TYPE_ARRAY) {
		char *end;
		uint64_t i;

		/* this can't be an address */
		if ((uintptr_t)key < 65536) {
			i = (uintptr_t)key;
		} else {
			errno = 0;
			i = strtoll(key, &end, 0);
			if (end == key || errno == ERANGE) {
				return &g_null_json;
			}
		}

		while (entry) {
			if (i-- == 0) {
				return entry;
			}
			entry = entry->next;
		}

		return &g_null_json;
	}

	while (entry) {
		if (strcmp(entry->key, key) == 0) {
			return entry;
		}
		entry = entry->next;
	}

	return &g_null_json;
}

struct cjson *
cjson_js_ext(size_t argc, ...)
{
	struct cjson *obj;
	va_list ap;
	int i;

	va_start(ap, argc);
	obj = va_arg(ap, struct cjson *);
	for (i = 0; i < argc - 1; i++) {
		const char *key = va_arg(ap, const char *);

		obj = cjson_obj(obj, key);
	}
	va_end(ap);

	return obj;
}
