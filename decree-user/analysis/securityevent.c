#include "qemu.h"

struct input_source_event {
	bool computed, offset_valid;
	uint16_t reserved;
	uint32_t offset;
};

static int security_events_enabled = 0;

#if defined(CONFIG_TCG_INTERPRETER)
static int invalid_instr_from_input_event_id = -1;
static int invalid_mem_from_input_event_id = -1;

void notify_invalid_instruction_from_input(CPUArchState *env, DataTag tag)
{
	struct input_source_event data;

	if (!security_events_enabled)
		return;

	data.reserved = 0;

	if ((tag & DATA_TAG_TYPE_MASK) == DATA_TAG_COMPUTED_FROM_INPUT) {
		data.computed = 1;
		data.offset_valid = 0;
		data.offset = 0;
	} else if (is_tracking_data_offsets()) {
		data.computed = 0;
		data.offset_valid = 1;
		data.offset = DATA_TAG_GET_OFFSET(tag);
	} else {
		data.computed = 0;
		data.offset_valid = 0;
		data.offset = 0;
	}

	analysis_output_event(env, invalid_instr_from_input_event_id, &data, sizeof(data));
}

void notify_invalid_memory_access_from_input(CPUArchState *env, DataTag tag)
{
	struct input_source_event data;

	if (!security_events_enabled)
		return;

	data.reserved = 0;

	if ((tag & DATA_TAG_TYPE_MASK) == DATA_TAG_COMPUTED_FROM_INPUT) {
		data.computed = 1;
		data.offset_valid = 0;
		data.offset = 0;
	} else if (is_tracking_data_offsets()) {
		data.computed = 0;
		data.offset_valid = 1;
		data.offset = DATA_TAG_GET_OFFSET(tag);
	} else {
		data.computed = 0;
		data.offset_valid = 0;
		data.offset = 0;
	}

	analysis_output_event(env, invalid_mem_from_input_event_id, &data, sizeof(data));
}
#endif

static int activate_security_events(CPUArchState *env, int argc, char **argv)
{
#if defined(CONFIG_TCG_INTERPRETER)
	invalid_instr_from_input_event_id = analysis_create_named_event(env, "invalid_instr_from_input");
	invalid_mem_from_input_event_id = analysis_create_named_event(env, "invalid_mem_from_input");
#endif

	security_events_enabled = 1;
    return 1;
}

void init_security_event_analysis(void)
{
    register_analysis_type("securityevent", "Records potential security issues", activate_security_events);
}
