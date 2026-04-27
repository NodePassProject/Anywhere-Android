#include <jni.h>
#include "libyaml/include/yaml.h"
#include <string.h>
#include <stdlib.h>

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} strbuf_t;

static int strbuf_init(strbuf_t *sb, size_t initial_cap) {
    sb->data = (char *)malloc(initial_cap);
    if (sb->data == NULL) return 0;
    sb->data[0] = '\0';
    sb->len = 0;
    sb->cap = initial_cap;
    return 1;
}

static void strbuf_free(strbuf_t *sb) {
    if (sb->data != NULL) {
        free(sb->data);
        sb->data = NULL;
    }
    sb->len = 0;
    sb->cap = 0;
}

static int strbuf_ensure(strbuf_t *sb, size_t additional) {
    size_t needed = sb->len + additional + 1;
    if (needed <= sb->cap) return 1;
    size_t new_cap = sb->cap * 2;
    if (new_cap < needed) new_cap = needed;
    char *new_data = (char *)realloc(sb->data, new_cap);
    if (new_data == NULL) return 0;
    sb->data = new_data;
    sb->cap = new_cap;
    return 1;
}

static int strbuf_append(strbuf_t *sb, const char *str, size_t slen) {
    if (!strbuf_ensure(sb, slen)) return 0;
    memcpy(sb->data + sb->len, str, slen);
    sb->len += slen;
    sb->data[sb->len] = '\0';
    return 1;
}

static int strbuf_append_cstr(strbuf_t *sb, const char *str) {
    return strbuf_append(sb, str, strlen(str));
}

static int strbuf_append_char(strbuf_t *sb, char c) {
    return strbuf_append(sb, &c, 1);
}

static int strbuf_append_json_string(strbuf_t *sb, const char *str, size_t len) {
    if (!strbuf_append_char(sb, '"')) return 0;

    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)str[i];
        switch (c) {
            case '"':
                if (!strbuf_append_cstr(sb, "\\\"")) return 0;
                break;
            case '\\':
                if (!strbuf_append_cstr(sb, "\\\\")) return 0;
                break;
            case '\b':
                if (!strbuf_append_cstr(sb, "\\b")) return 0;
                break;
            case '\f':
                if (!strbuf_append_cstr(sb, "\\f")) return 0;
                break;
            case '\n':
                if (!strbuf_append_cstr(sb, "\\n")) return 0;
                break;
            case '\r':
                if (!strbuf_append_cstr(sb, "\\r")) return 0;
                break;
            case '\t':
                if (!strbuf_append_cstr(sb, "\\t")) return 0;
                break;
            default:
                if (c < 0x20) {
                    char esc[7];
                    snprintf(esc, sizeof(esc), "\\u%04x", c);
                    if (!strbuf_append_cstr(sb, esc)) return 0;
                } else {
                    if (!strbuf_append_char(sb, (char)c)) return 0;
                }
                break;
        }
    }

    if (!strbuf_append_char(sb, '"')) return 0;
    return 1;
}

#define MAX_DEPTH 128

typedef enum {
    CTX_NONE,
    CTX_MAPPING_KEY,
    CTX_MAPPING_VALUE,
    CTX_SEQUENCE
} context_type_t;

typedef struct {
    context_type_t type;
    int count;
} context_frame_t;

typedef struct {
    context_frame_t stack[MAX_DEPTH];
    int depth;
} context_t;

static void context_init(context_t *ctx) {
    ctx->depth = 0;
}

static context_frame_t *context_top(context_t *ctx) {
    if (ctx->depth <= 0) return NULL;
    return &ctx->stack[ctx->depth - 1];
}

static int context_push(context_t *ctx, context_type_t type) {
    if (ctx->depth >= MAX_DEPTH) return 0;
    ctx->stack[ctx->depth].type = type;
    ctx->stack[ctx->depth].count = 0;
    ctx->depth++;
    return 1;
}

static void context_pop(context_t *ctx) {
    if (ctx->depth > 0) ctx->depth--;
}

static int emit_separator(strbuf_t *sb, context_t *ctx) {
    context_frame_t *frame = context_top(ctx);
    if (frame == NULL) return 1;

    switch (frame->type) {
        case CTX_MAPPING_KEY:
            if (frame->count > 0) {
                if (!strbuf_append_char(sb, ',')) return 0;
            }
            break;
        case CTX_MAPPING_VALUE:
            if (!strbuf_append_char(sb, ':')) return 0;
            break;
        case CTX_SEQUENCE:
            if (frame->count > 0) {
                if (!strbuf_append_char(sb, ',')) return 0;
            }
            break;
        default:
            break;
    }
    return 1;
}

static void advance_context(context_t *ctx) {
    context_frame_t *frame = context_top(ctx);
    if (frame == NULL) return;

    switch (frame->type) {
        case CTX_MAPPING_KEY:
            frame->type = CTX_MAPPING_VALUE;
            break;
        case CTX_MAPPING_VALUE:
            frame->type = CTX_MAPPING_KEY;
            frame->count++;
            break;
        case CTX_SEQUENCE:
            frame->count++;
            break;
        default:
            break;
    }
}

static int yaml_to_json(const char *yaml_str, size_t yaml_len, strbuf_t *sb) {
    yaml_parser_t parser;
    yaml_event_t event;
    context_t ctx;

    context_init(&ctx);

    if (!yaml_parser_initialize(&parser)) return 0;

    yaml_parser_set_input_string(&parser,
                                 (const unsigned char *)yaml_str,
                                 yaml_len);

    int done = 0;
    int error = 0;

    while (!done && !error) {
        if (!yaml_parser_parse(&parser, &event)) {
            error = 1;
            break;
        }

        switch (event.type) {
            case YAML_STREAM_START_EVENT:
            case YAML_STREAM_END_EVENT:
            case YAML_DOCUMENT_START_EVENT:
            case YAML_DOCUMENT_END_EVENT:
                break;

            case YAML_MAPPING_START_EVENT:
                if (!emit_separator(sb, &ctx)) { error = 1; break; }
                if (!strbuf_append_char(sb, '{')) { error = 1; break; }
                if (!context_push(&ctx, CTX_MAPPING_KEY)) { error = 1; break; }
                break;

            case YAML_MAPPING_END_EVENT:
                context_pop(&ctx);
                if (!strbuf_append_char(sb, '}')) { error = 1; break; }
                advance_context(&ctx);
                break;

            case YAML_SEQUENCE_START_EVENT:
                if (!emit_separator(sb, &ctx)) { error = 1; break; }
                if (!strbuf_append_char(sb, '[')) { error = 1; break; }
                if (!context_push(&ctx, CTX_SEQUENCE)) { error = 1; break; }
                break;

            case YAML_SEQUENCE_END_EVENT:
                context_pop(&ctx);
                if (!strbuf_append_char(sb, ']')) { error = 1; break; }
                advance_context(&ctx);
                break;

            case YAML_SCALAR_EVENT: {
                const char *value = (const char *)event.data.scalar.value;
                size_t value_len = event.data.scalar.length;

                if (!emit_separator(sb, &ctx)) { error = 1; break; }
                if (!strbuf_append_json_string(sb, value, value_len)) {
                    error = 1;
                    break;
                }
                advance_context(&ctx);
                break;
            }

            case YAML_ALIAS_EVENT:
                /* Aliases not supported; emit null. */
                if (!emit_separator(sb, &ctx)) { error = 1; break; }
                if (!strbuf_append_cstr(sb, "null")) { error = 1; break; }
                advance_context(&ctx);
                break;

            case YAML_NO_EVENT:
                done = 1;
                break;
        }

        if (event.type == YAML_STREAM_END_EVENT) {
            done = 1;
        }

        yaml_event_delete(&event);
    }

    yaml_parser_delete(&parser);
    return !error;
}

JNIEXPORT jstring JNICALL
Java_com_argsment_anywhere_vpn_NativeBridge_nativeParseYaml(
        JNIEnv *env, jclass clazz, jstring yamlContent) {
    if (yamlContent == NULL) return NULL;

    const char *yamlCStr = (*env)->GetStringUTFChars(env, yamlContent, NULL);
    if (yamlCStr == NULL) return NULL;

    size_t yamlLen = (*env)->GetStringUTFLength(env, yamlContent);

    strbuf_t sb;
    if (!strbuf_init(&sb, yamlLen > 256 ? yamlLen : 256)) {
        (*env)->ReleaseStringUTFChars(env, yamlContent, yamlCStr);
        return NULL;
    }

    int ok = yaml_to_json(yamlCStr, yamlLen, &sb);

    (*env)->ReleaseStringUTFChars(env, yamlContent, yamlCStr);

    if (!ok) {
        strbuf_free(&sb);
        return NULL;
    }

    jstring result = (*env)->NewStringUTF(env, sb.data);
    strbuf_free(&sb);

    return result;
}
