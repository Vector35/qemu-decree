#include "qemu.h"

static int replay_fd = -1;
static int reading_replay = 0;
static uint32_t replay_flags = 0;
static uint32_t base_wall_time = 0;
static uint32_t start_wall_time = 0;

static int global_ordering_index = 0; /* FIXME: This needs to actually be global */

static int next_global_ordering_index()
{
    return global_ordering_index++;
}

static uint32_t get_physical_wall_time()
{
    struct timeval tv;
    uint64_t result;

    gettimeofday(&tv, NULL);

    /* This will likely overflow, but we are reporting a relative time so it doesn't matter */
    result = (uint32_t)tv.tv_sec * 1000000;
    result += (uint32_t)tv.tv_usec;
    return result;
}

static uint32_t get_current_wall_time()
{
    return get_physical_wall_time() - base_wall_time;
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

    hdr.magic = REPLAY_MAGIC;
    hdr.version = REPLAY_VERSION;
    hdr.binary_count = binary_count;
    hdr.seed = seed;
    hdr.flags = flags;
    if (write(replay_fd, &hdr, sizeof(hdr)) <= 0) {
        fprintf(stderr, "Writing to replay file failed\n");
        close(replay_fd);
        replay_fd = -1;
        return 0;
    }

    base_wall_time = get_physical_wall_time();
    return 1;
}

int replay_open(const char* filename)
{
    struct replay_header hdr;

    replay_fd = open(filename, O_RDONLY);
    if (replay_fd < 0) {
        fprintf(stderr, "Replay file '%s' could not be opened\n", filename);
        return 0;
    }

    if (read(replay_fd, &hdr, sizeof(hdr)) <= 0) {
        fprintf(stderr, "Reading from replay file failed\n");
        close(replay_fd);
        replay_fd = -1;
        return 0;
    }

    if (hdr.magic != REPLAY_MAGIC) {
        fprintf(stderr, "File given is not a valid replay file\n");
        close(replay_fd);
        replay_fd = -1;
        return 0;
    }

    if (hdr.version != REPLAY_VERSION) {
        fprintf(stderr, "Replay file is version %d, current is %d, not opening\n", hdr.version, REPLAY_VERSION);
        close(replay_fd);
        replay_fd = -1;
        return 0;
    }

    reading_replay = 1;
    replay_flags = hdr.flags;
    binary_count = hdr.binary_count;
    random_seed = hdr.seed;
    return 1;
}

void replay_close(void)
{
    if (replay_fd == -1)
        return;

    close(replay_fd);
    replay_fd = -1;
    reading_replay = 0;
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
    evt.global_ordering = next_global_ordering_index();
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

static void replay_read(void* data, size_t len)
{
    while (len > 0) {
        int result = read(replay_fd, data, len);
        if (result < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "Error writing to replay file\n");
            abort();
        } else if (result == 0) {
            fprintf(stderr, "Error writing to replay file\n");
            abort();
        }

        data = (char*)data + result;
        len -= result;
    }
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

    replay_read(evt, sizeof(struct replay_event));

    if (evt->data_length > (1 << 30)) {
        fprintf(stderr, "Replay event data length too large\n");
        abort();
    }

    data = malloc(evt->data_length);
    replay_read(data, evt->data_length);
    return data;
}

void free_replay_event(void* data)
{
    free(data);
}
