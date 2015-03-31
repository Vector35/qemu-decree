#include "qemu.h"
#include "asmx86/asmx86.h"

#define BRANCH_TYPE_CALL           0
#define BRANCH_TYPE_RETURN         1
#define BRANCH_TYPE_JUMP           2
#define BRANCH_TYPE_COND_NOT_TAKEN 3
#define BRANCH_TYPE_COND_TAKEN     4

struct branch_trace_event {
    uint32_t type;
    uint32_t from, to;
};

static int event_id = -1;

static int branch_trace_filter(CPUArchState *env, void *data, abi_ulong pc, struct Instruction *insn)
{
    if (insn->operation == CALL)
        return 1;
    if (insn->operation == JMP)
        return 1;
    if (insn->operation == CALLF)
        return 1;
    if (insn->operation == JMPF)
        return 1;
    if ((insn->operation >= JO) && (insn->operation <= JG))
        return 1;
    if ((insn->operation >= JCXZ) && (insn->operation <= JRCXZ))
        return 1;
    if (insn->operation == LOOP)
        return 1;
    if (insn->operation == LOOPE)
        return 1;
    if (insn->operation == LOOPNE)
        return 1;
    if (insn->operation == RETN)
        return 1;
    if (insn->operation == RETF)
        return 1;
    if (insn->operation == IRET)
        return 1;
    return 0;
}

static void branch_trace_after_insn(CPUArchState *env, void *data, target_ulong insn_eip, struct Instruction *insn)
{
    struct branch_trace_event event;
    event.from = insn_eip;
    event.to = env->eip;

    if ((insn->operation == CALL) || (insn->operation == CALLF))
        event.type = BRANCH_TYPE_CALL;
    else if ((insn->operation == RETN) || (insn->operation == RETF) || (insn->operation == IRET))
        event.type = BRANCH_TYPE_RETURN;
    else if ((insn->operation == JMP) || (insn->operation == JMPF))
        event.type = BRANCH_TYPE_JUMP;
    else if (event.to == (uint32_t)insn->operands[0].immediate)
        event.type = BRANCH_TYPE_COND_TAKEN;
    else
        event.type = BRANCH_TYPE_COND_NOT_TAKEN;

    analysis_output_event(env, event_id, &event, sizeof(event));
}

static int activate_branch_trace(CPUArchState *env, int argc, char **argv)
{
    event_id = analysis_create_named_event(env, "branch");
    add_insn_instrumentation(env, branch_trace_filter, NULL, branch_trace_after_insn, NULL);
    return 1;
}

void init_branch_trace_analysis(void)
{
    register_analysis_type("branchtrace", "Tracks all branches", activate_branch_trace);
}
