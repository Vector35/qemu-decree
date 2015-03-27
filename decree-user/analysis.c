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

/* During event writing we don't actually know the correct wall time, since we need to know the
   number of instructions between replay events (which have the actual wall times recorded).  To
   handle this, we will update the event buffer with the correct wall time retroactively once we
   reach the next replay event.  This variable will track where in the output buffer the next
   event without a calculated wall time is, if this is the same as consumed_output_buffer then
   all events have accurate wall times. */
static size_t wall_time_update_offset = 0;

/* If there are a large number of events between wall time updates, some events which have not
   yet had a wall time calculated may need to be flushed to disk.  Also track file offsets of
   wall time updates for this reason. */
static uint64_t wall_time_file_offset = 0;
static uint64_t current_file_offset = 0;

/* Keep track of prior replay event's instructions retired count and wall clock time, so that
   wall clock times for the instructions in between can be calculated. */
static uint32_t prev_wall_time = 0;
static uint64_t prev_insn_retired = 0;

static void output_read(void* data, size_t len)
{
    while (len > 0) {
        int result = read(output_fd, data, len);
        if (result < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "Error reading from analysis output file\n");
            abort();
        } else if (result == 0) {
            fprintf(stderr, "Error reading from analysis output file\n");
            abort();
        }

        data = (char*)data + result;
        len -= result;
    }
}

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

static void output_buffered_write(const void* data, size_t len)
{
    if ((consumed_output_buffer + len) > OUTPUT_BUFFER_SIZE) {
        /* Update the total file size and the file offset of the last event that has valid wall time */
        wall_time_file_offset += wall_time_update_offset;
        current_file_offset += consumed_output_buffer;

        /* Write the buffer to the file */
        output_write(output_buffer, consumed_output_buffer);

        /* Reset buffer state */
        consumed_output_buffer = 0;
        wall_time_update_offset = 0;
    }

    if (len > OUTPUT_BUFFER_SIZE) {
        /* Event is too big for the buffer */
        current_file_offset += len;
        output_write(data, len);
        return;
    }

    memcpy(&output_buffer[consumed_output_buffer], data, len);
    consumed_output_buffer += len;
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
    current_file_offset = sizeof(hdr);
    wall_time_file_offset = sizeof(hdr);
    return 1;
}

void analysis_output_close()
{
    if (output_fd < 0)
        return;

    if ((consumed_output_buffer != wall_time_update_offset) ||
        (current_file_offset != wall_time_file_offset)) {
        /* Some of the events do not have a valid wall time, this is an error.  Make sure to
           call analysis_sync_wall_time before finalizing. */
        fprintf(stderr, "Closing analysis output file but some events do not have a valid wall clock time\n");
        abort();
    }

    /* Flush write buffer before closing */
    if (consumed_output_buffer > 0) {
        output_write(output_buffer, consumed_output_buffer);
        consumed_output_buffer = 0;
    }

    close(output_fd);
    g_free(output_buffer);
    output_buffer = NULL;
}

void analysis_sync_wall_time(CPUArchState *env, uint32_t event_wall_time, uint32_t resume_wall_time)
{
    if (event_wall_time == 0) {
        /* Events may have a start time of zero, this indicates the call did not block and we should
           just make the start and end times match */
        event_wall_time = resume_wall_time;
    }

    uint64_t cur_insn_retired = env->insn_retired;
    uint64_t total_insn = cur_insn_retired - prev_insn_retired;
    double prev_time = (double)prev_wall_time / 1000000.0;
    double total_time = ((double)(event_wall_time - prev_wall_time)) / 1000000.0;
    double per_insn_time = (total_insn > 0) ? (total_time / (double)total_insn) : 0;

    while (wall_time_file_offset < current_file_offset) {
        /* Some events on disk have not been updated, update them now */
        struct analysis_event_header hdr;
        if (lseek(output_fd, wall_time_file_offset, SEEK_SET) < 0) {
            fprintf(stderr, "Failed to seek when updating analysis output event wall time\n");
            abort();
        }
        output_read(&hdr, sizeof(hdr));

        hdr.wall_time = prev_time + (per_insn_time * (double)(hdr.insn_count - prev_insn_retired));

        if (lseek(output_fd, wall_time_file_offset, SEEK_SET) < 0) {
            fprintf(stderr, "Failed to seek when updating analysis output event wall time\n");
            abort();
        }
        output_write(&hdr, sizeof(hdr));

        wall_time_file_offset += sizeof(hdr) + hdr.length;
        if (wall_time_file_offset > current_file_offset) {
            /* Went past known current position, events are invalid */
            fprintf(stderr, "Analysis output events misaligned in file\n");
            abort();
        }
    }

    while (wall_time_update_offset < consumed_output_buffer) {
        /* Update in-memory events for wall time calculation */
        struct analysis_event_header hdr;
        if ((wall_time_update_offset + sizeof(hdr)) > consumed_output_buffer) {
            /* Header not complete */
            fprintf(stderr, "Analysis output events are invalid\n");
            abort();
        }

        memcpy(&hdr, &output_buffer[wall_time_update_offset], sizeof(hdr));
        hdr.wall_time = prev_time + (per_insn_time * (double)(hdr.insn_count - prev_insn_retired));
        memcpy(&output_buffer[wall_time_update_offset], &hdr, sizeof(hdr));

        wall_time_update_offset += sizeof(hdr) + hdr.length;
        if (wall_time_update_offset > consumed_output_buffer) {
            fprintf(stderr, "Analysis output events misaligned in memory\n");
            abort();
        }
    }

    /* Save time and instruction count for next replay event */
    prev_wall_time = resume_wall_time;
    prev_insn_retired = cur_insn_retired;
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
    hdr.wall_time = 0; /* Will be updated by analysis_sync_wall_time */
    hdr.insn_count = env->insn_retired;
    output_buffered_write(&hdr, sizeof(hdr));

    if (len != 0)
        output_buffered_write(data, len);
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
}

void init_analysis()
{
    init_call_trace_analysis();
}
