#include "qemu.h"

struct InstrumentationState instrumentation = {
    .insn_instrumentation = QTAILQ_HEAD_INITIALIZER(instrumentation.insn_instrumentation)
};

InsnInstrumentation *add_insn_instrumentation(CPUArchState *env, InsnInstrumentationFilterFn filter,
                                              InsnInstrumentationFn before, InsnInstrumentationFn after,
                                              void *data)
{
    InsnInstrumentation *instrument;

    instrument = g_malloc(sizeof(*instrument));

    instrument->data = data;
    instrument->filter = filter;
    instrument->before = before;
    instrument->after = after;

    QTAILQ_INSERT_TAIL(&instrumentation.insn_instrumentation, instrument, entry);

    tb_flush(env);
    return instrument;
}

void remove_insn_instrumentation(CPUArchState *env, InsnInstrumentation *instrument)
{
    QTAILQ_REMOVE(&instrumentation.insn_instrumentation, instrument, entry);
    tb_flush(env);
    g_free(instrument);
}
