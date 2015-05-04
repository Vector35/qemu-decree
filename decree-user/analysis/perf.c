#include "qemu.h"

struct perf_event {
    /* Instruction count is implicitly included in the event header */
    uint32_t mem_pages;
};

static int event_id = -1;

static void record_perf(CPUArchState *env, void *data, int sig)
{
    struct perf_event event;
    (void)data;
    (void)sig;
    event.mem_pages = 0; /* FIXME: Track this during execution */
    analysis_output_event(env, event_id, &event, sizeof(event));
}

static int activate_perf_analysis(CPUArchState *env, int argc, char **argv)
{
    event_id = analysis_create_named_event(env, "perf");
    add_exit_callback(record_perf, NULL);
    return 1;
}

void init_perf_analysis(void)
{
    register_analysis_type("perf", "Gathers memory and CPU usage statistics", activate_perf_analysis);
}
