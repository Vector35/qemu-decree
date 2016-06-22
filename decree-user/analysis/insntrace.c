#include "qemu.h"
#include "asmx86/asmx86.h"

struct insn_trace_event {
    uint32_t eip;
    uint8_t bytes[0];
};

struct insn_trace_with_regs_event {
    uint32_t eip;
    uint32_t eax, ecx, edx, ebx;
    uint32_t esp, ebp, esi, edi;
    uint8_t bytes[0];
};

static int event_id = -1;
int ready_for_trace = 0;
int enable_syscall_trace = 1;

static int populate_insn_bytes(void *data, target_ulong insn_eip, struct Instruction *insn)
{
    void *p;

    if (insn->length > 15)
        return 0;

    if ((p = lock_user(VERIFY_READ, insn_eip, insn->length, 1)) == NULL)
        return 0;
    memcpy(data, p, insn->length);
    unlock_user(p, insn_eip, 0);

    return 1;
}

static void populate_insn_disasm(void *data, target_ulong insn_eip, struct Instruction *insn, size_t max_len)
{
    FormatInstructionString((char*)data, max_len, "%i %o", NULL, insn_eip, insn);
}

static void insn_trace_before_insn(CPUArchState *env, void *data, target_ulong insn_eip, struct Instruction *insn)
{
    union
    {
        struct insn_trace_event data;
        uint8_t storage[sizeof(struct insn_trace_event) + 15];
    } event;

    if ((insn->operation == INT) && ((env->regs[R_EAX] == 2) || (env->regs[R_EAX] == 3))) {
        ready_for_trace = 1;
        enable_syscall_trace = 1;
    }
    if (!ready_for_trace) {
        return;
    }

    event.data.eip = insn_eip;
    if (populate_insn_bytes(event.data.bytes, insn_eip, insn))
        analysis_output_event(env, event_id, &event, sizeof(struct insn_trace_event) + insn->length);
}

static void insn_trace_before_insn_disasm(CPUArchState *env, void *data, target_ulong insn_eip, struct Instruction *insn)
{
    union
    {
        struct insn_trace_event data;
        uint8_t storage[sizeof(struct insn_trace_event) + 64];
    } event;

    if ((insn->operation == INT) && ((env->regs[R_EAX] == 2) || (env->regs[R_EAX] == 3))) {
        ready_for_trace = 1;
        enable_syscall_trace = 1;
    }
    if (!ready_for_trace) {
        return;
    }

    event.data.eip = insn_eip;
    populate_insn_disasm(event.data.bytes, insn_eip, insn, 63);
    analysis_output_event(env, event_id, &event, sizeof(struct insn_trace_event) + strlen((char*)event.data.bytes));
}

static void insn_trace_before_insn_regs(CPUArchState *env, void *data, target_ulong insn_eip, struct Instruction *insn)
{
    union
    {
        struct insn_trace_with_regs_event data;
        uint8_t storage[sizeof(struct insn_trace_with_regs_event) + 15];
    } event;

    if ((insn->operation == INT) && ((env->regs[R_EAX] == 2) || (env->regs[R_EAX] == 3))) {
        ready_for_trace = 1;
        enable_syscall_trace = 1;
    }
    if (!ready_for_trace) {
        return;
    }

    event.data.eip = insn_eip;
    event.data.eax = env->regs[R_EAX];
    event.data.ecx = env->regs[R_ECX];
    event.data.edx = env->regs[R_EDX];
    event.data.ebx = env->regs[R_EBX];
    event.data.esp = env->regs[R_ESP];
    event.data.ebp = env->regs[R_EBP];
    event.data.esi = env->regs[R_ESI];
    event.data.edi = env->regs[R_EDI];

    if (populate_insn_bytes(event.data.bytes, insn_eip, insn))
        analysis_output_event(env, event_id, &event, sizeof(struct insn_trace_with_regs_event) + insn->length);
}

static void insn_trace_before_insn_regs_disasm(CPUArchState *env, void *data, target_ulong insn_eip, struct Instruction *insn)
{
    union
    {
        struct insn_trace_with_regs_event data;
        uint8_t storage[sizeof(struct insn_trace_with_regs_event) + 64];
    } event;

    if ((insn->operation == INT) && ((env->regs[R_EAX] == 2) || (env->regs[R_EAX] == 3))) {
        ready_for_trace = 1;
        enable_syscall_trace = 1;
    }
    if (!ready_for_trace) {
        return;
    }

    event.data.eip = insn_eip;
    event.data.eax = env->regs[R_EAX];
    event.data.ecx = env->regs[R_ECX];
    event.data.edx = env->regs[R_EDX];
    event.data.ebx = env->regs[R_EBX];
    event.data.esp = env->regs[R_ESP];
    event.data.ebp = env->regs[R_EBP];
    event.data.esi = env->regs[R_ESI];
    event.data.edi = env->regs[R_EDI];

    populate_insn_disasm(event.data.bytes, insn_eip, insn, 63);
    analysis_output_event(env, event_id, &event, sizeof(struct insn_trace_with_regs_event) + strlen((char*)event.data.bytes));
}

static int activate_insn_trace(CPUArchState *env, int argc, char **argv)
{
    int regs = 0;
    int disasm = 0;
    int i;

    enable_syscall_trace = 0;

    for (i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "regs"))
            regs = 1;
        else if (!strcmp(argv[i], "disasm"))
            disasm = 1;
    }

    if (!regs && !disasm) {
        event_id = analysis_create_named_event(env, "instruction");
        add_insn_instrumentation(env, NULL, insn_trace_before_insn, NULL, NULL);
    } else if (regs && !disasm) {
        event_id = analysis_create_named_event(env, "instruction_regs");
        add_insn_instrumentation(env, NULL, insn_trace_before_insn_regs, NULL, NULL);
    } else if (!regs && disasm) {
        event_id = analysis_create_named_event(env, "instruction_disasm");
        add_insn_instrumentation(env, NULL, insn_trace_before_insn_disasm, NULL, NULL);
    } else if (regs && disasm) {
        event_id = analysis_create_named_event(env, "instruction_regs_disasm");
        add_insn_instrumentation(env, NULL, insn_trace_before_insn_regs_disasm, NULL, NULL);
    }
    return 1;
}

void init_insn_trace_analysis(void)
{
    register_analysis_type("itrace", "Records all instructions (optional args: regs, disasm)", activate_insn_trace);
}
