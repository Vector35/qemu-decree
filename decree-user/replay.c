/*
 * Deterministic record/replay system for Cyber Grand Challenge DECREE binaries
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

#include <zlib.h>
#include "qemu.h"

static int replay_fd = -1;
static gzFile replay_zlib_file;
static int reading_replay = 0;
static int reading_compressed = 0;
static int writing_replay = 0;
static int multi_binary_replay = 0;
static uint32_t replay_flags = 0;
static uint32_t start_wall_time = 0;

static int next_global_ordering_index()
{
    return __sync_fetch_and_add(&shared->global_ordering_index, 1);
}

uint32_t get_physical_wall_time()
{
    struct timeval tv;
    uint64_t result;

    gettimeofday(&tv, NULL);

    /* This will likely overflow, but we are reporting a relative time so it doesn't matter */
    result = (uint32_t)tv.tv_sec * 1000000;
    result += (uint32_t)tv.tv_usec;
    return result;
}

uint32_t get_current_wall_time()
{
    return get_physical_wall_time() - shared->base_wall_time;
}

static void replay_write(const void* data, size_t len)
{
    if (len > (1 << 30)) {
        fprintf(stderr, "Replay event data length too large\n");
        abort();
    }

    while (len > 0) {
        int result = write(replay_fd, data, len);
        if (result < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "Error writing to replay file\n");
            abort();
        } else if (result == 0) {
            fprintf(stderr, "Error writing to replay file\n");
            abort();
        }

        data = (const char*)data + result;
        len -= result;
    }
}

int replay_create(const char* filename, uint32_t flags, uint32_t seed)
{
    struct replay_header hdr;

    replay_fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (replay_fd < 0) {
        fprintf(stderr, "Replay file '%s' could not be written\n", filename);
        return 0;
    }

    replay_flags = flags;
    writing_replay = 1;

    hdr.magic = REPLAY_MAGIC;
    hdr.version = REPLAY_VERSION;
    hdr.binary_count = binary_count;
    hdr.seed = seed;
    hdr.flags = flags;
    replay_write(&hdr, sizeof(hdr));
    return 1;
}

static int replay_read(void* data, size_t len)
{
    if (reading_compressed) {
        return gzread(replay_zlib_file, data, (unsigned)len) == len;
    }

    while (len > 0) {
        int result = read(replay_fd, data, len);
        if (result < 0) {
            if (errno == EINTR)
                continue;
            return 0;
        } else if (result == 0) {
            return 0;
        }

        data = (char*)data + result;
        len -= result;
    }
    return 1;
}

int replay_open(const char* filename)
{
    struct replay_header hdr;

    /* Save whether we are actually running more than one binary, the binary_count variable will
       be overwritten during the replay process to ensure the file descriptor state is valid. */
    multi_binary_replay = (binary_count > 1);

    reading_compressed = 0;
    replay_fd = open(filename, O_RDONLY);
    if (replay_fd < 0) {
        fprintf(stderr, "Replay file '%s' could not be opened\n", filename);
        return 0;
    }

    if ((!replay_read(&hdr, sizeof(hdr))) || (hdr.magic != REPLAY_MAGIC)) {
        /* Magic is not valid, check for gzip */
        close(replay_fd);
        replay_fd = -1;

        reading_compressed = 1;
        replay_zlib_file = gzopen(filename, "rb");
        if (!replay_zlib_file) {
            fprintf(stderr, "File given is not a valid replay file\n");
            return 0;
        }

        if ((!replay_read(&hdr, sizeof(hdr))) || (hdr.magic != REPLAY_MAGIC)) {
            fprintf(stderr, "File given is not a valid replay file\n");
            gzclose(replay_zlib_file);
            replay_zlib_file = NULL;
            return 0;
        }
    }

    if (hdr.version != REPLAY_VERSION) {
        fprintf(stderr, "Replay file is version %d, current is %d, not opening\n", hdr.version, REPLAY_VERSION);
        if (reading_compressed) {
            gzclose(replay_zlib_file);
            replay_zlib_file = NULL;
        } else {
            close(replay_fd);
            replay_fd = -1;
        }
        return 0;
    }

    reading_replay = 1;
    replay_flags = hdr.flags;
    binary_count = hdr.binary_count;
    random_seed = hdr.seed;
    return 1;
}

int replay_close(int signal)
{
    int result = 1;

    if ((!reading_replay) && (!writing_replay))
        return 1;

    if (reading_replay) {
        /* When playing back, ensure that the termination condition is expected. The termination event
           does not have a global ordering index, so do not synchronize here. */
        struct replay_event evt;

        if ((signal == TARGET_SIGINT) || (signal == TARGET_SIGABRT)) {
            /* Do not validate termination condition when user interrupts the replay or the replay aborts */
            result = 1;
        } else if (!replay_read(&evt, sizeof(struct replay_event))) {
            fprintf(stderr, "Replay file truncated\n");
            result = 0;
        } else if (evt.event_id != REPLAY_EVENT_TERMINATE) {
            fprintf(stderr, "Process terminated early\n");
            result = 0;
        } else if ((signal == 0) && (evt.result != 0)) {
            fprintf(stderr, "Expected signal %d, but process terminated normally\n", evt.result);
            result = 0;
        } else if ((signal != 0) && (evt.result == 0)) {
            fprintf(stderr, "Unexpected signal %d during replay\n", signal);
            result = 0;
        } else if (signal != evt.result) {
            fprintf(stderr, "Expected signal %d, got signal %d\n", evt.result, signal);
            result = 0;
        }
    }

    if (writing_replay) {
        /* When closing a record session, add an end event to track the time of exit and the signal if any. */
        start_wall_time = 0;
        replay_write_event(REPLAY_EVENT_TERMINATE, 0, signal);
    }

    if (reading_replay && reading_compressed) {
        gzclose(replay_zlib_file);
        replay_zlib_file = NULL;
    } else {
        close(replay_fd);
        replay_fd = -1;
    }
    reading_replay = 0;
    writing_replay = 0;
    return result;
}

void replay_begin_event()
{
    start_wall_time = get_current_wall_time();
}

void replay_nonblocking_event()
{
    /* Events that do not block will get a start time of zero */
    start_wall_time = 0;
}

void replay_write_event(uint16_t id, uint16_t fd, uint32_t result)
{
    struct replay_event evt;

    if (replay_fd == -1)
        return;

    evt.event_id = id;
    evt.fd = fd;

    if (id == REPLAY_EVENT_TERMINATE) {
        /* Termination event should not increment global ordering, to avoid locking while in a signal
           handler.  A process terminating will not impact the other processes, so it is safe. The
           original order will still be recoverable using the wall time fields. */
        evt.global_ordering = 0;
    } else {
        evt.global_ordering = next_global_ordering_index();
    }

    evt.result = result;
    evt.data_length = 0;
    evt.start_wall_time = start_wall_time;
    evt.end_wall_time = get_current_wall_time();

    replay_write(&evt, sizeof(evt));
}

void replay_write_event_with_required_data(uint16_t id, uint16_t fd, uint32_t result, const void *data, size_t len)
{
    struct replay_event evt;

    if (replay_fd == -1)
        return;

    evt.event_id = id;
    evt.fd = fd;
    evt.global_ordering = next_global_ordering_index();
    evt.result = result;
    evt.data_length = len;
    evt.start_wall_time = start_wall_time;
    evt.end_wall_time = get_current_wall_time();

    replay_write(&evt, sizeof(evt));
    replay_write(data, len);
}

void replay_write_event_with_validation_data(uint16_t id, uint16_t fd, uint32_t result, const void *data, size_t len)
{
    struct replay_event evt;

    if (replay_fd == -1)
        return;

    evt.event_id = id;
    evt.fd = fd;
    evt.global_ordering = next_global_ordering_index();
    evt.result = result;
    evt.data_length = (replay_flags & REPLAY_FLAG_COMPACT) ? 0 : len;
    evt.start_wall_time = start_wall_time;
    evt.end_wall_time = get_current_wall_time();

    replay_write(&evt, sizeof(evt));
    if (!(replay_flags & REPLAY_FLAG_COMPACT))
        replay_write(data, len);
}

void replay_write_validation_event(uint16_t id, uint16_t fd, uint32_t result, const void *data, size_t len)
{
    struct replay_event evt;

    if (replay_fd == -1)
        return;
    if (replay_flags & REPLAY_FLAG_COMPACT)
        return;

    evt.event_id = id;
    evt.fd = fd;
    evt.global_ordering = next_global_ordering_index();
    evt.result = result;
    evt.data_length = len;
    evt.start_wall_time = start_wall_time;
    evt.end_wall_time = get_current_wall_time();

    replay_write(&evt, sizeof(evt));
    replay_write(data, len);
}

int is_replaying(void)
{
    return reading_replay;
}

int replay_has_validation(void)
{
    return (replay_flags & REPLAY_FLAG_COMPACT) == 0;
}

void* read_replay_event(struct replay_event* evt)
{
    void* data;

    if (!replay_read(evt, sizeof(struct replay_event))) {
        fprintf(stderr, "Replay file truncated\n");
        abort();
    }

    if (evt->data_length > (1 << 30)) {
        fprintf(stderr, "Replay event data length too large\n");
        abort();
    }

    data = malloc(evt->data_length);
    if (!replay_read(data, evt->data_length)) {
        fprintf(stderr, "Replay file data could not be read\n");
        abort();
    }

    /* For multi-binary replays, do only one syscall at a time to guarantee the original ordering */
    if (multi_binary_replay) {
        pthread_mutex_lock(&shared->syscall_ordering_mutex);

        while (evt->global_ordering != shared->global_ordering_index) {
            /* This syscall is not supposed to happen yet according to the global ordering stored
               in the replay file.  Wait for the other processes to catch up. */
            if (pthread_cond_wait(&shared->syscall_ordering_cond, &shared->syscall_ordering_mutex) != 0) {
                fprintf(stderr, "Replay synchronization failed\n");
                abort();
            }
        }
    }

    return data;
}

void free_replay_event(void* data)
{
    /* Syscall is complete, increment global ordering counter and let the next syscall execute */
    if (multi_binary_replay) {
        next_global_ordering_index();
        pthread_cond_broadcast(&shared->syscall_ordering_cond);
        pthread_mutex_unlock(&shared->syscall_ordering_mutex);
    }

    free(data);
}
