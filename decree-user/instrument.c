/*
 * Per-instruction instrumentation API
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

struct InstrumentationState instrumentation = {
    .insn_instrumentation = QTAILQ_HEAD_INITIALIZER(instrumentation.insn_instrumentation),
    .exit_callbacks = QTAILQ_HEAD_INITIALIZER(instrumentation.exit_callbacks),
    .read_callbacks = QTAILQ_HEAD_INITIALIZER(instrumentation.read_callbacks),
    .write_callbacks = QTAILQ_HEAD_INITIALIZER(instrumentation.write_callbacks)
};

int memory_trace_enabled = 0;

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

ExitCallback *add_exit_callback(ExitCallbackFn cb, void *data)
{
    ExitCallback *entry;

    entry = g_malloc(sizeof(*entry));
    entry->data = data;
    entry->callback = cb;

    QTAILQ_INSERT_TAIL(&instrumentation.exit_callbacks, entry, entry);
    return entry;
}

void remove_exit_callback(ExitCallback *cb)
{
    QTAILQ_REMOVE(&instrumentation.exit_callbacks, cb, entry);
    g_free(cb);
}

void notify_exit(CPUArchState *env, int sig)
{
    ExitCallback *cb;

    QTAILQ_FOREACH(cb, &instrumentation.exit_callbacks, entry) {
        cb->callback(env, cb->data, sig);
    }
}

ReadWriteCallback *add_memory_read_callback(CPUArchState *env, ReadWriteCallbackFn cb, void *data)
{
    ReadWriteCallback *entry;

    entry = g_malloc(sizeof(*entry));
    entry->data = data;
    entry->callback = cb;

    QTAILQ_INSERT_TAIL(&instrumentation.read_callbacks, entry, entry);

    memory_trace_enabled = 1;
    tb_flush(env);
    return entry;
}

ReadWriteCallback *add_memory_write_callback(CPUArchState *env, ReadWriteCallbackFn cb, void *data)
{
    ReadWriteCallback *entry;

    entry = g_malloc(sizeof(*entry));
    entry->data = data;
    entry->callback = cb;

    QTAILQ_INSERT_TAIL(&instrumentation.write_callbacks, entry, entry);

    memory_trace_enabled = 1;
    tb_flush(env);
    return entry;
}

void remove_memory_read_callback(CPUArchState *env, ReadWriteCallback *cb)
{
    QTAILQ_REMOVE(&instrumentation.read_callbacks, cb, entry);
    g_free(cb);

	if (QTAILQ_EMPTY(&instrumentation.read_callbacks) &&
	    QTAILQ_EMPTY(&instrumentation.write_callbacks)) {
		memory_trace_enabled = 0;
		tb_flush(env);
	}
}

void remove_memory_write_callback(CPUArchState *env, ReadWriteCallback *cb)
{
    QTAILQ_REMOVE(&instrumentation.write_callbacks, cb, entry);
    g_free(cb);

	if (QTAILQ_EMPTY(&instrumentation.read_callbacks) &&
	    QTAILQ_EMPTY(&instrumentation.write_callbacks)) {
		memory_trace_enabled = 0;
		tb_flush(env);
	}
}

void notify_memory_read(CPUArchState *env, abi_ulong addr, abi_ulong size, abi_ulong value)
{
    ReadWriteCallback *cb;

    if (size < sizeof(value))
	    value &= (1 << (size * 8)) - 1;

    QTAILQ_FOREACH(cb, &instrumentation.read_callbacks, entry) {
	    cb->callback(env, cb->data, addr, size, value);
    }
}

void notify_memory_write(CPUArchState *env, abi_ulong addr, abi_ulong size, abi_ulong value)
{
    ReadWriteCallback *cb;

    if (size < sizeof(value))
	    value &= (1 << (size * 8)) - 1;

    QTAILQ_FOREACH(cb, &instrumentation.write_callbacks, entry) {
	    cb->callback(env, cb->data, addr, size, value);
    }
}
