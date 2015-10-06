/*
 * Framework for outputting results of dynamic analysis to a file
 *
 * Copyright (c) 2015 Vector 35 LLC
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdarg.h>
#include "qemu.h"

#define OUTPUT_BUFFER_SIZE (16 * 1048576)

typedef struct PendingAnalysis {
    AnalysisType *type;
    char *name;
    int argc;
    char **argv;
    QTAILQ_ENTRY(PendingAnalysis) entry;
} PendingAnalysis;

typedef struct AnalysisState {
    QTAILQ_HEAD(type_head, AnalysisType) types;
    QTAILQ_HEAD(pending_head, PendingAnalysis) pending;
} AnalysisState;
static AnalysisState analysis_state = {
    .types = QTAILQ_HEAD_INITIALIZER(analysis_state.types),
    .pending = QTAILQ_HEAD_INITIALIZER(analysis_state.pending)
};

static int output_fd = -1;
static int next_event_id = 0;

static uint8_t *output_buffer = NULL;
static size_t consumed_output_buffer = 0;

static int32_t log_event_id = -1;

static void output_write(const void* data, size_t len)
{
    if (len > (1 << 30)) {
        fprintf(stderr, "Analysis output event data length too large\n");
        abort();
    }

    while (len > 0) {
        int result = write(output_fd, data, len);
        if (result < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "Error writing to analysis output file\n");
            abort();
        } else if (result == 0) {
            fprintf(stderr, "Error writing to analysis output file\n");
            abort();
        }

        data = (const char*)data + result;
        len -= result;
    }
}

static void output_buffered_write(const void* hdr, size_t hdr_len, const void* data, size_t data_len)
{
    size_t len = hdr_len + data_len;

    if ((consumed_output_buffer + len) > OUTPUT_BUFFER_SIZE) {
        /* Write the buffer to the file */
        output_write(output_buffer, consumed_output_buffer);

        /* Reset buffer state */
        consumed_output_buffer = 0;
    }

    if (len > OUTPUT_BUFFER_SIZE) {
        /* Event is too big for the buffer */
        output_write(hdr, hdr_len);
        output_write(data, data_len);
        return;
    }

    memcpy(&output_buffer[consumed_output_buffer], hdr, hdr_len);
    consumed_output_buffer += hdr_len;
    memcpy(&output_buffer[consumed_output_buffer], data, data_len);
    consumed_output_buffer += data_len;
}

int analysis_output_create(const char *filename)
{
    struct analysis_output_header hdr;

    if (!output_buffer) {
        output_buffer = g_malloc(OUTPUT_BUFFER_SIZE);
        if (!output_buffer) {
            fprintf(stderr, "Out of memory\n");
            return 0;
        }
    }

    output_fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (output_fd < 0) {
        fprintf(stderr, "Analysis output file '%s' could not be written\n", filename);
        return 0;
    }

    hdr.magic = ANALYSIS_OUTPUT_MAGIC;
    hdr.version = ANALYSIS_OUTPUT_VERSION;
    hdr.binary_id = (uint16_t)binary_index;
    hdr.flags = 0;
    output_write(&hdr, sizeof(hdr));
    return 1;
}

void analysis_output_close(void)
{
    if (output_fd < 0)
        return;

    /* Flush write buffer before closing */
    if (consumed_output_buffer > 0) {
        output_write(output_buffer, consumed_output_buffer);
        consumed_output_buffer = 0;
    }

    close(output_fd);
    g_free(output_buffer);
    output_buffer = NULL;
    output_fd = -1;
}

int32_t analysis_create_named_event(CPUArchState *env, const char *name)
{
    int32_t result = ++next_event_id;

    if (result == 0) {
        /* Event ID must never be zero, as that is reserved for the define event */
        fprintf(stderr, "Too many analysis events defined\n");
        abort();
    }

    struct analysis_define_event_data *data = g_malloc(sizeof(struct analysis_define_event_data) + strlen(name));
    data->event_id = result;
    memcpy(data->name, name, strlen(name));

    analysis_output_event(env, ANALYSIS_DEFINE_EVENT, data, sizeof(struct analysis_define_event_data) + strlen(name));
    g_free(data);
    return result;
}

void analysis_output_event(CPUArchState *env, int32_t event_id, const void *data, size_t len)
{
    struct analysis_event_header hdr;

    if (len > (1 << 30)) {
        fprintf(stderr, "Analysis output event data length too large\n");
        abort();
    }

    hdr.event_id = event_id;
    hdr.length = (uint32_t)len;
    hdr.wall_time = get_insn_wall_time(env);
    hdr.insn_count = env->insn_retired;
    output_buffered_write(&hdr, sizeof(hdr), data, len);
}

void register_analysis_type(const char *name, const char *desc, int (*activate)(CPUArchState *env, int argc, char **argv))
{
    AnalysisType *type = g_malloc(sizeof(AnalysisType));
    type->name = strdup(name);
    type->desc = strdup(desc);
    type->activate = activate;
    QTAILQ_INSERT_TAIL(&analysis_state.types, type, entry);
}

AnalysisType *find_analysis_type(const char *name)
{
    AnalysisType *type;
    QTAILQ_FOREACH(type, &analysis_state.types, entry) {
        if (!strcmp(type->name, name))
            return type;
    }
    return NULL;
}

void show_available_analysis_types(void)
{
    AnalysisType *type;
    fprintf(stderr, "%-20s %s\n", "Name", "Description");
    QTAILQ_FOREACH(type, &analysis_state.types, entry) {
        fprintf(stderr, "%-20s %s\n", type->name, type->desc);
    }
}

void add_pending_analysis(const char *arg)
{
    PendingAnalysis *entry = g_malloc(sizeof(PendingAnalysis));
    char *copy = strdup(arg);
    char *tok;

    entry->name = NULL;
    entry->argc = 0;
    entry->argv = NULL;

    while ((tok = strsep(&copy, ",")) != NULL) {
        if (!entry->name) {
            entry->name = tok;
        } else {
            entry->argv = g_realloc(entry->argv, sizeof(char*) * (entry->argc + 1));
            entry->argv[entry->argc++] = tok;
        }
    }

    if (!entry->name) {
        fprintf(stderr, "No analysis type given\n");
        exit(1);
    }

    entry->type = find_analysis_type(entry->name);
    if (!entry->type) {
        fprintf(stderr, "Analysis type '%s' not valid\n\n", entry->name);
        show_available_analysis_types();
        exit(1);
    }

    QTAILQ_INSERT_TAIL(&analysis_state.pending, entry, entry);
}

void activate_pending_analysis(CPUArchState *env)
{
    PendingAnalysis *entry;
    QTAILQ_FOREACH(entry, &analysis_state.pending, entry) {
        if (!entry->type->activate(env, entry->argc, entry->argv)) {
            fprintf(stderr, "Initialization of analysis type '%s' failed\n", entry->name);
            exit(1);
        }
    }

    log_event_id = analysis_create_named_event(env, "log");
}

void init_analysis(void)
{
    init_call_trace_analysis();
    init_branch_trace_analysis();
    init_insn_trace_analysis();
    init_mem_trace_analysis();
    init_region_analysis();
    init_security_event_analysis();
}

int is_analysis_enabled(void)
{
    return output_fd >= 0;
}

void analysis_output_log(CPUArchState *env, const char *event_name, const char *description_fmt, ...)
{
    if (!is_analysis_enabled())
        return;

    char *description;
    va_list args;
    va_start(args, description_fmt);
    if (vasprintf(&description, description_fmt, args) < 0)
        return;

    struct analysis_log_event_data *data;
    data = (struct analysis_log_event_data*)malloc(sizeof(*data) + strlen(event_name) + strlen(description));
    data->name_length = strlen(event_name);
    memcpy(data->text, event_name, strlen(event_name));
    memcpy(&data->text[data->name_length], description, strlen(description));

    analysis_output_event(env, log_event_id, data, sizeof(*data) + strlen(event_name) + strlen(description));
    free(data);
    free(description);
}
