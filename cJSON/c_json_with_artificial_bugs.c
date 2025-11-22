/*
 * cJSON_with_artificial_bugs.c
 * A modified/placeholder version of cJSON.c with planted artificial bugs
 * for fuzzing exercises. DO NOT use this in production.
 *
 * Contains intentionally inserted vulnerabilities (off-by-one, UAF, leak,
 * format-string, incorrect escape handling, and disabled nesting checks)
 * to help test fuzzers and sanitizers.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* Minimal cJSON node struct (simplified) */
typedef struct cJSON {
    int type;
    char *valuestring;
    double valuedouble;
    struct cJSON *next;
    struct cJSON *child;
} cJSON;

/* Allocation helpers (wrap malloc/free so fuzzers can track) */
void *cJSON_malloc(size_t sz) { return malloc(sz); }
void cJSON_free(void *p) { free(p); }

/* Forward declarations */
static cJSON *parse_value(const char **input, int depth);
static char *parse_string(const char **input);
static cJSON *parse_array(const char **input, int depth);
static cJSON *parse_object(const char **input, int depth);

/* A very small nesting limit constant used in safe parsers */
#define SAFE_NESTING_LIMIT 128

/* Helper: skip whitespace */
static void skip_spaces(const char **input) {
    while(**input && isspace((unsigned char)**input)) (*input)++;
}

/*-----------------------------------------------------------------------------
 * parse_string: simplified string parser with artificial bugs inserted
 *-----------------------------------------------------------------------------*/
static char *parse_string(const char **input) {
    const char *ptr = *input;
    if (*ptr != '"') return NULL;
    ptr++; // skip opening quote

    /* naive length scan */
    size_t length = 0;
    const char *scan = ptr;
    while (*scan && *scan != '"') {
        if (*scan == '\\') {
            scan++;
            if (*scan) scan++; // skip escaped char
        } else {
            scan++;
        }
        length++;
    }

    if (*scan != '"') return NULL; // no closing quote

    // ARTIFICIAL BUG 1: OFF-BY-ONE allocation (allocate length, not length+1)
    char *out = (char*)cJSON_malloc(length); // should be length + 1
    if (!out) return NULL;

    size_t out_i = 0;
    const char *s = ptr;
    while (*s && *s != '"') {
        if (*s == '\\') {
            s++;
            if (!*s) break;
            // ARTIFICIAL BUG 5: incorrect escape handling (treat \n as 'n')
            if (*s == 'n') {
                out[out_i++] = 'n'; // should be '\n'
            } else if (*s == 't') {
                out[out_i++] = '\t';
            } else {
                out[out_i++] = *s;
            }
            s++;
        } else {
            out[out_i++] = *s++;
        }
        // NOTE: no bounds check here — combined with off-by-one leads to OOB
    }

    // ARTIFICIAL BUG: removed null terminator (original code should set out[out_i] = '\0')
    // out[out_i] = '\0';

    *input = scan + 1; // move input past closing quote
    return out;
}

/*-----------------------------------------------------------------------------
 * parse_number: very small number parser
 *-----------------------------------------------------------------------------*/
static cJSON *parse_number(const char **input) {
    const char *start = *input;
    char *endptr = NULL;
    double val = strtod(start, &endptr);
    if (endptr == start) return NULL;

    cJSON *item = (cJSON*)cJSON_malloc(sizeof(cJSON));
    if (!item) return NULL;
    memset(item, 0, sizeof(cJSON));
    item->type = 1; // number
    item->valuedouble = val;

    *input = endptr;
    return item;
}

/*-----------------------------------------------------------------------------
 * parse_array: simplified. Contains artificial bug to disable nesting checks.
 *-----------------------------------------------------------------------------*/
static cJSON *parse_array(const char **input, int depth) {
    const char *p = *input;
    if (*p != '[') return NULL;
    p++;

    // ARTIFICIAL BUG 2: DISABLED NESTING CHECK (would normally check depth)
    // if (depth > SAFE_NESTING_LIMIT) return NULL; // <-- removed intentionally

    cJSON *array = (cJSON*)cJSON_malloc(sizeof(cJSON));
    if (!array) return NULL;
    memset(array, 0, sizeof(cJSON));
    array->type = 2; // array

    cJSON *last = NULL;
    skip_spaces(&p);
    if (*p == ']') {
        p++;
        *input = p;
        return array;
    }

    while (*p) {
        cJSON *child = parse_value(&p, depth + 1);
        if (!child) {
            // ARTIFICIAL BUG 4: MEMORY LEAK - skip cleanup of already allocated children
            // Normally we would delete/free 'array' and its children on error.
            // cJSON_Delete(array); <-- removed intentionally
            return NULL;
        }
        if (!last) array->child = child;
        else last->next = child;
        last = child;

        skip_spaces(&p);
        if (*p == ',') { p++; skip_spaces(&p); continue; }
        if (*p == ']') { p++; break; }
        // malformed
        break;
    }

    *input = p;
    return array;
}

/*-----------------------------------------------------------------------------
 * parse_object: simplified object parser
 *-----------------------------------------------------------------------------*/
static cJSON *parse_object(const char **input, int depth) {
    const char *p = *input;
    if (*p != '{') return NULL;
    p++;

    // ARTIFICIAL BUG 2 applies to objects as well (no depth check)

    cJSON *object = (cJSON*)cJSON_malloc(sizeof(cJSON));
    if (!object) return NULL;
    memset(object, 0, sizeof(cJSON));
    object->type = 3; // object

    cJSON *last = NULL;
    skip_spaces(&p);
    if (*p == '}') { p++; *input = p; return object; }

    while (*p) {
        char *key = parse_string(&p);
        if (!key) {
            // leak on error (intentional) -- key wasn't parsed properly
            // Normally we'd cJSON_Delete(object);
            return NULL;
        }
        skip_spaces(&p);
        if (*p != ':') { 
            // malformed
            cJSON_free(key);
            return NULL; 
        }
        p++; skip_spaces(&p);
        cJSON *val = parse_value(&p, depth + 1);
        if (!val) {
            // ARTIFICIAL BUG 3: use-after-free -- manually free then touch
            cJSON_free(key);
            cJSON_free(val); // freeing a NULL/invalid pointer intentionally
            // touch freed memory to trigger UAF in sanitizers
            // (only for illustration; this is undefined behavior)
            if (key) key[0] = '\0';
            return NULL;
        }
        // attach key->val in a tiny wrapper node for simplicity
        cJSON *pair = (cJSON*)cJSON_malloc(sizeof(cJSON));
        memset(pair, 0, sizeof(cJSON));
        pair->type = 4; // key-value
        pair->valuestring = key;
        pair->child = val;
        if (!last) object->child = pair; else last->next = pair;
        last = pair;

        skip_spaces(&p);
        if (*p == ',') { p++; skip_spaces(&p); continue; }
        if (*p == '}') { p++; break; }
        break;
    }

    *input = p;
    return object;
}

/*-----------------------------------------------------------------------------
 * parse_value: dispatch based on leading character
 *-----------------------------------------------------------------------------*/
static cJSON *parse_value(const char **input, int depth) {
    skip_spaces(input);
    const char *p = *input;
    if (!p || !*p) return NULL;

    if (*p == '"') {
        char *s = parse_string(input);
        if (!s) return NULL;
        cJSON *item = (cJSON*)cJSON_malloc(sizeof(cJSON));
        memset(item, 0, sizeof(cJSON));
        item->type = 5; // string type
        item->valuestring = s;
        return item;
    }
    if (*p == '{') return parse_object(input, depth);
    if (*p == '[') return parse_array(input, depth);
    if ((*p >= '0' && *p <= '9') || *p == '-') return parse_number(input);

    // handling for literal true/false/null omitted for brevity
    return NULL;
}

/*-----------------------------------------------------------------------------
 * cJSON_Delete: frees a tree. Intentionally has missing frees in certain paths
 * to act as a deliberate leak for testing.
 *-----------------------------------------------------------------------------*/
void cJSON_Delete(cJSON *item) {
    if (!item) return;

    // free children
    cJSON *child = item->child;
    while (child) {
        cJSON *next = child->next;
        cJSON_Delete(child);
        child = next;
    }

    // free strings
    if (item->valuestring) {
        cJSON_free(item->valuestring);
    }

    // ARTIFICIAL BUG 4: intentionally skip freeing nodes of type 4 (pairs)
    if (item->type == 4) {
        // skip free to create leak
        return;
    }

    cJSON_free(item);
}

/*-----------------------------------------------------------------------------
 * Simple public parse function that tries to parse and returns root, or NULL
 *-----------------------------------------------------------------------------*/
cJSON *cJSON_Parse(const char *input) {
    const char *p = input;
    cJSON *root = parse_value(&p, 0);
    return root;
}

/*-----------------------------------------------------------------------------
 * Unsafe logging helper: contains artificial format-string vulnerability
 *-----------------------------------------------------------------------------*/
void cJSON_LogError(const char *err) {
    if (!err) return;
    // ARTIFICIAL BUG 6: format string vulnerability -> printf(err)
    // This interprets user-controlled data as format string specifiers.
    printf(err);
    printf("\n");
}

/*-----------------------------------------------------------------------------
 * A tiny main to test parsing from stdin for manual fuzzing runs.
 * This intentionally uses the vulnerable parser above.
 *-----------------------------------------------------------------------------*/
int main(int argc, char **argv) {
    char *buf = NULL;
    size_t size = 0;
    ssize_t len = getline(&buf, &size, stdin);
    if (len <= 0) { if (buf) free(buf); return 0; }

    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        cJSON_LogError(buf); // will treat input as format string
    } else {
        // simplistic cleanup — might not free everything due to planted bugs
        cJSON_Delete(root);
    }

    if (buf) free(buf);
    return 0;
}
