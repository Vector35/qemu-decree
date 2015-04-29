#include "qemu.h"
#include "asmx86/asmx86.h"

struct call_trace_event {
    uint32_t from, to, stack_ptr;
};

static int call_event_id = -1;
static int return_event_id = -1;

static int call_trace_filter(CPUArchState *env, void *data, abi_ulong pc, struct Instruction *insn)
{
    if (insn->operation == CALL)
        return 1;
    if (insn->operation == RETN)
        return 1;
    return 0;
}

static void call_trace_after_insn(CPUArchState *env, void *data, abi_ulong insn_eip, struct Instruction *insn)
{
    int event_id;
    struct call_trace_event event;
    event.from = insn_eip;
    event.to = env->eip;
    event.stack_ptr = env->regs[R_ESP];

    if (insn->operation == CALL)
        event_id = call_event_id;
    else if (insn->operation == RETN)
        event_id = return_event_id;
    else
        return;

    analysis_output_event(env, event_id, &event, sizeof(event));
}

static int activate_call_trace(CPUArchState *env, int argc, char **argv)
{
    call_event_id = analysis_create_named_event(env, "calltrace_call");
    return_event_id = analysis_create_named_event(env, "calltrace_return");
    add_insn_instrumentation(env, call_trace_filter, NULL, call_trace_after_insn, NULL);
    return 1;
}

void init_call_trace_analysis(void)
{
    register_analysis_type("calltrace", "Tracks function entry and exit", activate_call_trace);
}
