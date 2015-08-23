#include "qemu.h"

struct mem_trace_event {
	abi_ulong addr;
	abi_ulong value;
};

static int read_event_id = -1;
static int write_event_id = -1;

static void read_callback(CPUArchState *env, void *data, abi_ulong addr, abi_ulong size, abi_ulong value)
{
	struct mem_trace_event event;

	if (unlikely(size > sizeof(event.value))) {
		fprintf(stderr, "Memory read size larger than native integer\n");
		abort();
	}

	event.addr = addr;
	event.value = value;
	analysis_output_event(env, read_event_id, &event, sizeof(uint32_t) + size);
}

static void write_callback(CPUArchState *env, void *data, abi_ulong addr, abi_ulong size, abi_ulong value)
{
	struct mem_trace_event event;

	if (unlikely(size > sizeof(event.value))) {
		fprintf(stderr, "Memory write size larger than native integer\n");
		abort();
	}

	event.addr = addr;
	event.value = value;
	analysis_output_event(env, write_event_id, &event, sizeof(uint32_t) + size);
}

static int activate_mem_trace(CPUArchState *env, int argc, char **argv)
{
	read_event_id = analysis_create_named_event(env, "mem_read");
	write_event_id = analysis_create_named_event(env, "mem_write");
	add_memory_read_callback(env, read_callback, NULL);
	add_memory_write_callback(env, write_callback, NULL);
    return 1;
}

void init_mem_trace_analysis(void)
{
    register_analysis_type("memtrace", "Records all memory reads and writes", activate_mem_trace);
}
