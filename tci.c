/*
 * Tiny Code Interpreter for QEMU
 *
 * Copyright (c) 2009, 2011 Stefan Weil
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"

/* Defining NDEBUG disables assertions (which makes the code faster). */
#if !defined(CONFIG_DEBUG_TCG) && !defined(NDEBUG)
# define NDEBUG
#endif

#include "qemu-common.h"
#include "exec/exec-all.h"           /* MAX_OPC_PARAM_IARGS */
#include "exec/cpu_ldst.h"
#include "tcg-op.h"
#if defined(CONFIG_DECREE_USER)
#include "qemu.h"
#endif

/* Marker for missing code. */
#define TODO() \
    do { \
        fprintf(stderr, "TODO %s:%u: %s()\n", \
                __FILE__, __LINE__, __func__); \
        tcg_abort(); \
    } while (0)

#if MAX_OPC_PARAM_IARGS != 5
# error Fix needed, number of supported input arguments changed!
#endif
#if TCG_TARGET_REG_BITS == 32
typedef uint64_t (*helper_function)(tcg_target_ulong, tcg_target_ulong,
                                    tcg_target_ulong, tcg_target_ulong,
                                    tcg_target_ulong, tcg_target_ulong,
                                    tcg_target_ulong, tcg_target_ulong,
                                    tcg_target_ulong, tcg_target_ulong);
#else
typedef uint64_t (*helper_function)(tcg_target_ulong, tcg_target_ulong,
                                    tcg_target_ulong, tcg_target_ulong,
                                    tcg_target_ulong);
#endif

/* Targets which don't use GETPC also don't need tci_tb_ptr
   which makes them a little faster. */
#if defined(GETPC)
uintptr_t tci_tb_ptr;
#endif

static tcg_target_ulong tci_reg[TCG_TARGET_NB_REGS];
static DataTag tci_reg_tag[TCG_TARGET_NB_REGS] = {0};
static DataTag env_tag[sizeof(CPUArchState)] = {0};
static DataTag helper_result_tag = 0;
static DataTag mem_addr_tag = 0;

static int track_data_offsets = 1;

typedef union
{
    DataTag *full_tags;
    uint8_t *minimal_tags;
} DataTagPage;

DataTagPage mem_tag[1 << (32 - DATA_TAG_PAGE_BITS)] = {{0}};

int is_tracking_data_offsets(void)
{
    return track_data_offsets;
}

void set_tracking_data_offsets(int track)
{
    track_data_offsets = track;
}

void set_helper_result_tag(DataTag tag)
{
    helper_result_tag = tag;
}

DataTag get_mem_addr_tag(void)
{
    return mem_addr_tag;
}

DataTag read_env_tag(long offset, long size)
{
    DataTag result, next;
    tcg_target_ulong i;

    if ((offset + size) > sizeof(CPUArchState))
        return 0;

    result = env_tag[offset];
    for (i = 1; i < size; i++) {
        next = env_tag[offset + i];
        if ((result & DATA_TAG_TYPE_MASK) != (next & DATA_TAG_TYPE_MASK)) {
            if ((result & DATA_TAG_INPUT) || (next & DATA_TAG_INPUT))
                return DATA_TAG_COMPUTED_FROM_INPUT;
            result = 0;
        }
    }
    return result;
}

void write_env_tag(CPUArchState *env, long offset, long size, DataTag tag)
{
    tcg_target_ulong i;
    if ((offset + size) > sizeof(CPUArchState))
        return;
    if (((tag & DATA_TAG_TYPE_MASK) == DATA_TAG_INPUT) || ((tag & DATA_TAG_TYPE_MASK) == DATA_TAG_SENSITIVE_DATA)) {
        for (i = 0; i < size; i++) {
            env_tag[offset + i] = tag + i;
        }
    } else {
        for (i = 0; i < size; i++) {
            env_tag[offset + i] = tag;
        }
    }
}

static DataTag read_mem_byte_tag(vaddr addr)
{
    addr &= 0xffffffff;
    if (track_data_offsets) {
        if (mem_tag[addr >> DATA_TAG_PAGE_BITS].full_tags)
            return mem_tag[addr >> DATA_TAG_PAGE_BITS].full_tags[addr & DATA_TAG_PAGE_MASK];
        return 0;
    } else {
        if (mem_tag[addr >> DATA_TAG_PAGE_BITS].minimal_tags) {
            uint8_t value = mem_tag[addr >> DATA_TAG_PAGE_BITS].minimal_tags[(addr & DATA_TAG_PAGE_MASK) >> 2];
            return ((uint32_t)(value >> ((addr & 3) * 2))) << 30;
        }
        return 0;
    }
}

DataTag read_mem_tag(vaddr addr, long size)
{
    DataTag result, next;
    tcg_target_ulong i;

    result = read_mem_byte_tag(addr);
    for (i = 1; i < size; i++) {
        next = read_mem_byte_tag(addr + i);
        if ((result & DATA_TAG_TYPE_MASK) != (next & DATA_TAG_TYPE_MASK)) {
            if ((result & DATA_TAG_INPUT) || (next & DATA_TAG_INPUT))
                return DATA_TAG_COMPUTED_FROM_INPUT;
            result = 0;
        }
    }
    return result;
}

static void write_mem_byte_tag(vaddr addr, DataTag tag)
{
    addr &= 0xffffffff;
    if (track_data_offsets) {
        if (!mem_tag[addr >> DATA_TAG_PAGE_BITS].full_tags) {
            mem_tag[addr >> DATA_TAG_PAGE_BITS].full_tags = g_malloc0(sizeof(DataTag) * DATA_TAG_PAGE_SIZE);
        }
        mem_tag[addr >> DATA_TAG_PAGE_BITS].full_tags[addr & DATA_TAG_PAGE_MASK] = tag;
    } else {
        uint8_t value;
        if (!mem_tag[addr >> DATA_TAG_PAGE_BITS].minimal_tags) {
            mem_tag[addr >> DATA_TAG_PAGE_BITS].minimal_tags = g_malloc0(DATA_TAG_PAGE_SIZE / 4);
        }
        value = mem_tag[addr >> DATA_TAG_PAGE_BITS].minimal_tags[(addr & DATA_TAG_PAGE_MASK) >> 2];
        value &= ~(3 << ((addr & 3) * 2));
        value |= (uint8_t)((tag >> 30) << ((addr & 3) * 2));
        mem_tag[addr >> DATA_TAG_PAGE_BITS].minimal_tags[(addr & DATA_TAG_PAGE_MASK) >> 2] = value;
    }
}

void write_mem_tag(CPUArchState *env, vaddr addr, long size, DataTag tag)
{
    long i;
    if (((tag & DATA_TAG_TYPE_MASK) == DATA_TAG_INPUT) || ((tag & DATA_TAG_TYPE_MASK) == DATA_TAG_SENSITIVE_DATA)) {
        for (i = 0; i < size; i++) {
            write_mem_byte_tag(addr + i, tag + i);
        }
    } else {
        for (i = 0; i < size; i++) {
            write_mem_byte_tag(addr + i, tag);
        }
    }
}

void free_mem_tags(vaddr addr, long size)
{
    long i;
    if ((addr & DATA_TAG_PAGE_MASK) || (size & DATA_TAG_PAGE_MASK))
        abort();
    for (i = 0; i < size; i += DATA_TAG_PAGE_SIZE) {
        vaddr cur = (addr + i) & 0xffffffff;
        if (track_data_offsets) {
            if (mem_tag[cur >> DATA_TAG_PAGE_BITS].full_tags) {
                g_free(mem_tag[cur >> DATA_TAG_PAGE_BITS].full_tags);
                mem_tag[cur >> DATA_TAG_PAGE_BITS].full_tags = NULL;
            }
        } else {
            if (mem_tag[cur >> DATA_TAG_PAGE_BITS].minimal_tags) {
                g_free(mem_tag[cur >> DATA_TAG_PAGE_BITS].minimal_tags);
                mem_tag[cur >> DATA_TAG_PAGE_BITS].minimal_tags = NULL;
            }
        }
    }
}

static tcg_target_ulong tci_read_reg(TCGReg index, DataTag* tag)
{
    assert(index < ARRAY_SIZE(tci_reg));
    if (tag)
        *tag = tci_reg_tag[index];
    return tci_reg[index];
}

#if TCG_TARGET_HAS_ext8s_i32 || TCG_TARGET_HAS_ext8s_i64
static int8_t tci_read_reg8s(TCGReg index, DataTag* tag)
{
    return (int8_t)tci_read_reg(index, tag);
}
#endif

#if TCG_TARGET_HAS_ext16s_i32 || TCG_TARGET_HAS_ext16s_i64
static int16_t tci_read_reg16s(TCGReg index, DataTag* tag)
{
    return (int16_t)tci_read_reg(index, tag);
}
#endif

#if TCG_TARGET_REG_BITS == 64
static int32_t tci_read_reg32s(TCGReg index, DataTag* tag)
{
    return (int32_t)tci_read_reg(index, tag);
}
#endif

static uint8_t tci_read_reg8(TCGReg index, DataTag* tag)
{
    return (uint8_t)tci_read_reg(index, tag);
}

static uint16_t tci_read_reg16(TCGReg index, DataTag* tag)
{
    return (uint16_t)tci_read_reg(index, tag);
}

static uint32_t tci_read_reg32(TCGReg index, DataTag* tag)
{
    return (uint32_t)tci_read_reg(index, tag);
}

#if TCG_TARGET_REG_BITS == 64
static uint64_t tci_read_reg64(TCGReg index, DataTag* tag)
{
    return tci_read_reg(index, tag);
}
#endif

static void tci_write_reg(TCGReg index, tcg_target_ulong value, DataTag tag)
{
    assert(index < ARRAY_SIZE(tci_reg));
    assert(index != TCG_AREG0);
    assert(index != TCG_REG_CALL_STACK);
    tci_reg[index] = value;
    tci_reg_tag[index] = tag;
}

#if TCG_TARGET_REG_BITS == 64
static void tci_write_reg32s(TCGReg index, int32_t value, DataTag tag)
{
    tci_write_reg(index, value, tag);
}
#endif

static void tci_write_reg8(TCGReg index, uint8_t value, DataTag tag)
{
    tci_write_reg(index, value, tag);
}

static void tci_write_reg32(TCGReg index, uint32_t value, DataTag tag)
{
    tci_write_reg(index, value, tag);
}

#if TCG_TARGET_REG_BITS == 32
static void tci_write_reg64(uint32_t high_index, uint32_t low_index,
                            uint64_t value, DataTag tag)
{
    tci_write_reg(low_index, value, tag);
    tci_write_reg(high_index, value >> 32, tag);
}
#elif TCG_TARGET_REG_BITS == 64
static void tci_write_reg64(TCGReg index, uint64_t value, DataTag tag)
{
    tci_write_reg(index, value, tag);
}
#endif

#if TCG_TARGET_REG_BITS == 32
/* Create a 64 bit value from two 32 bit values. */
static uint64_t tci_uint64(uint32_t high, uint32_t low)
{
    return ((uint64_t)high << 32) + low;
}
#endif

/* Read constant (native size) from bytecode. */
static tcg_target_ulong tci_read_i(uint8_t **tb_ptr)
{
    tcg_target_ulong value = *(tcg_target_ulong *)(*tb_ptr);
    *tb_ptr += sizeof(value);
    return value;
}

/* Read unsigned constant (32 bit) from bytecode. */
static uint32_t tci_read_i32(uint8_t **tb_ptr)
{
    uint32_t value = *(uint32_t *)(*tb_ptr);
    *tb_ptr += sizeof(value);
    return value;
}

/* Read signed constant (32 bit) from bytecode. */
static int32_t tci_read_s32(uint8_t **tb_ptr)
{
    int32_t value = *(int32_t *)(*tb_ptr);
    *tb_ptr += sizeof(value);
    return value;
}

#if TCG_TARGET_REG_BITS == 64
/* Read constant (64 bit) from bytecode. */
static uint64_t tci_read_i64(uint8_t **tb_ptr)
{
    uint64_t value = *(uint64_t *)(*tb_ptr);
    *tb_ptr += sizeof(value);
    return value;
}
#endif

/* Read indexed register (native size) from bytecode. */
static tcg_target_ulong tci_read_r(uint8_t **tb_ptr, DataTag* tag)
{
    tcg_target_ulong value = tci_read_reg(**tb_ptr, tag);
    *tb_ptr += 1;
    return value;
}

/* Read indexed register (8 bit) from bytecode. */
static uint8_t tci_read_r8(uint8_t **tb_ptr, DataTag* tag)
{
    uint8_t value = tci_read_reg8(**tb_ptr, tag);
    *tb_ptr += 1;
    return value;
}

#if TCG_TARGET_HAS_ext8s_i32 || TCG_TARGET_HAS_ext8s_i64
/* Read indexed register (8 bit signed) from bytecode. */
static int8_t tci_read_r8s(uint8_t **tb_ptr, DataTag* tag)
{
    int8_t value = tci_read_reg8s(**tb_ptr, tag);
    *tb_ptr += 1;
    return value;
}
#endif

/* Read indexed register (16 bit) from bytecode. */
static uint16_t tci_read_r16(uint8_t **tb_ptr, DataTag* tag)
{
    uint16_t value = tci_read_reg16(**tb_ptr, tag);
    *tb_ptr += 1;
    return value;
}

#if TCG_TARGET_HAS_ext16s_i32 || TCG_TARGET_HAS_ext16s_i64
/* Read indexed register (16 bit signed) from bytecode. */
static int16_t tci_read_r16s(uint8_t **tb_ptr, DataTag* tag)
{
    int16_t value = tci_read_reg16s(**tb_ptr, tag);
    *tb_ptr += 1;
    return value;
}
#endif

/* Read indexed register (32 bit) from bytecode. */
static uint32_t tci_read_r32(uint8_t **tb_ptr, DataTag* tag)
{
    uint32_t value = tci_read_reg32(**tb_ptr, tag);
    *tb_ptr += 1;
    return value;
}

static DataTag combine_tags(DataTag a, DataTag b)
{
    if ((a & DATA_TAG_INPUT) || (b & DATA_TAG_INPUT))
        return DATA_TAG_COMPUTED_FROM_INPUT;
    return 0;
}

#if TCG_TARGET_REG_BITS == 32
/* Read two indexed registers (2 * 32 bit) from bytecode. */
static uint64_t tci_read_r64(uint8_t **tb_ptr, DataTag* tag)
{
    DataTag low_tag, high_tag;
    uint32_t low = tci_read_r32(tb_ptr, &low_tag);
    uint64_t result = tci_uint64(tci_read_r32(tb_ptr, high_tag), low);
    if (tag)
        *tag = combine_tags(low_tag, high_tag);
    return result;
}
#elif TCG_TARGET_REG_BITS == 64
/* Read indexed register (32 bit signed) from bytecode. */
static int32_t tci_read_r32s(uint8_t **tb_ptr, DataTag* tag)
{
    int32_t value = tci_read_reg32s(**tb_ptr, tag);
    *tb_ptr += 1;
    return value;
}

/* Read indexed register (64 bit) from bytecode. */
static uint64_t tci_read_r64(uint8_t **tb_ptr, DataTag* tag)
{
    uint64_t value = tci_read_reg64(**tb_ptr, tag);
    *tb_ptr += 1;
    return value;
}
#endif

/* Read indexed register(s) with target address from bytecode. */
static target_ulong tci_read_ulong(uint8_t **tb_ptr, DataTag* tag)
{
    target_ulong taddr = tci_read_r(tb_ptr, tag);
#if TARGET_LONG_BITS > TCG_TARGET_REG_BITS
    DataTag high_tag;
    taddr += (uint64_t)tci_read_r(tb_ptr, high_tag) << 32;
    if (tag)
        *tag = combine_tags(*tag, high_tag);
#endif
    return taddr;
}

/* Read indexed register or constant (native size) from bytecode. */
static tcg_target_ulong tci_read_ri(uint8_t **tb_ptr, DataTag* tag)
{
    tcg_target_ulong value;
    TCGReg r = **tb_ptr;
    *tb_ptr += 1;
    if (r == TCG_CONST) {
        value = tci_read_i(tb_ptr);
        if (tag)
            *tag = 0;
    } else {
        value = tci_read_reg(r, tag);
    }
    return value;
}

/* Read indexed register or constant (32 bit) from bytecode. */
static uint32_t tci_read_ri32(uint8_t **tb_ptr, DataTag* tag)
{
    uint32_t value;
    TCGReg r = **tb_ptr;
    *tb_ptr += 1;
    if (r == TCG_CONST) {
        value = tci_read_i32(tb_ptr);
        if (tag)
            *tag = 0;
    } else {
        value = tci_read_reg32(r, tag);
    }
    return value;
}

#if TCG_TARGET_REG_BITS == 32
/* Read two indexed registers or constants (2 * 32 bit) from bytecode. */
static uint64_t tci_read_ri64(uint8_t **tb_ptr, DataTag* tag)
{
    DataTag low_tag, high_tag;
    uint32_t low = tci_read_ri32(tb_ptr, &low_tag);
    uint64_t result = tci_uint64(tci_read_ri32(tb_ptr, &high_tag), low);
    if (tag)
        *tag = combine_tags(low_tag, high_tag);
    return result;
}
#elif TCG_TARGET_REG_BITS == 64
/* Read indexed register or constant (64 bit) from bytecode. */
static uint64_t tci_read_ri64(uint8_t **tb_ptr, DataTag* tag)
{
    uint64_t value;
    TCGReg r = **tb_ptr;
    *tb_ptr += 1;
    if (r == TCG_CONST) {
        value = tci_read_i64(tb_ptr);
        if (tag)
            *tag = 0;
    } else {
        value = tci_read_reg64(r, tag);
    }
    return value;
}
#endif

static tcg_target_ulong tci_read_label(uint8_t **tb_ptr)
{
    tcg_target_ulong label = tci_read_i(tb_ptr);
    assert(label != 0);
    return label;
}

static bool tci_compare32(uint32_t u0, uint32_t u1, TCGCond condition)
{
    bool result = false;
    int32_t i0 = u0;
    int32_t i1 = u1;
    switch (condition) {
    case TCG_COND_EQ:
        result = (u0 == u1);
        break;
    case TCG_COND_NE:
        result = (u0 != u1);
        break;
    case TCG_COND_LT:
        result = (i0 < i1);
        break;
    case TCG_COND_GE:
        result = (i0 >= i1);
        break;
    case TCG_COND_LE:
        result = (i0 <= i1);
        break;
    case TCG_COND_GT:
        result = (i0 > i1);
        break;
    case TCG_COND_LTU:
        result = (u0 < u1);
        break;
    case TCG_COND_GEU:
        result = (u0 >= u1);
        break;
    case TCG_COND_LEU:
        result = (u0 <= u1);
        break;
    case TCG_COND_GTU:
        result = (u0 > u1);
        break;
    default:
        TODO();
    }
    return result;
}

static bool tci_compare64(uint64_t u0, uint64_t u1, TCGCond condition)
{
    bool result = false;
    int64_t i0 = u0;
    int64_t i1 = u1;
    switch (condition) {
    case TCG_COND_EQ:
        result = (u0 == u1);
        break;
    case TCG_COND_NE:
        result = (u0 != u1);
        break;
    case TCG_COND_LT:
        result = (i0 < i1);
        break;
    case TCG_COND_GE:
        result = (i0 >= i1);
        break;
    case TCG_COND_LE:
        result = (i0 <= i1);
        break;
    case TCG_COND_GT:
        result = (i0 > i1);
        break;
    case TCG_COND_LTU:
        result = (u0 < u1);
        break;
    case TCG_COND_GEU:
        result = (u0 >= u1);
        break;
    case TCG_COND_LEU:
        result = (u0 <= u1);
        break;
    case TCG_COND_GTU:
        result = (u0 > u1);
        break;
    default:
        TODO();
    }
    return result;
}

#ifdef CONFIG_SOFTMMU
# define mmuidx          tci_read_i(&tb_ptr)
# define qemu_ld_ub \
    helper_ret_ldub_mmu(env, taddr, mmuidx, (uintptr_t)tb_ptr)
# define qemu_ld_leuw \
    helper_le_lduw_mmu(env, taddr, mmuidx, (uintptr_t)tb_ptr)
# define qemu_ld_leul \
    helper_le_ldul_mmu(env, taddr, mmuidx, (uintptr_t)tb_ptr)
# define qemu_ld_leq \
    helper_le_ldq_mmu(env, taddr, mmuidx, (uintptr_t)tb_ptr)
# define qemu_ld_beuw \
    helper_be_lduw_mmu(env, taddr, mmuidx, (uintptr_t)tb_ptr)
# define qemu_ld_beul \
    helper_be_ldul_mmu(env, taddr, mmuidx, (uintptr_t)tb_ptr)
# define qemu_ld_beq \
    helper_be_ldq_mmu(env, taddr, mmuidx, (uintptr_t)tb_ptr)
# define qemu_st_b(X) \
    helper_ret_stb_mmu(env, taddr, X, mmuidx, (uintptr_t)tb_ptr)
# define qemu_st_lew(X) \
    helper_le_stw_mmu(env, taddr, X, mmuidx, (uintptr_t)tb_ptr)
# define qemu_st_lel(X) \
    helper_le_stl_mmu(env, taddr, X, mmuidx, (uintptr_t)tb_ptr)
# define qemu_st_leq(X) \
    helper_le_stq_mmu(env, taddr, X, mmuidx, (uintptr_t)tb_ptr)
# define qemu_st_bew(X) \
    helper_be_stw_mmu(env, taddr, X, mmuidx, (uintptr_t)tb_ptr)
# define qemu_st_bel(X) \
    helper_be_stl_mmu(env, taddr, X, mmuidx, (uintptr_t)tb_ptr)
# define qemu_st_beq(X) \
    helper_be_stq_mmu(env, taddr, X, mmuidx, (uintptr_t)tb_ptr)
#else
# define qemu_ld_ub      ldub_p(g2h(taddr))
# define qemu_ld_leuw    lduw_le_p(g2h(taddr))
# define qemu_ld_leul    (uint32_t)ldl_le_p(g2h(taddr))
# define qemu_ld_leq     ldq_le_p(g2h(taddr))
# define qemu_ld_beuw    lduw_be_p(g2h(taddr))
# define qemu_ld_beul    (uint32_t)ldl_be_p(g2h(taddr))
# define qemu_ld_beq     ldq_be_p(g2h(taddr))
# define qemu_st_b(X)    stb_p(g2h(taddr), X)
# define qemu_st_lew(X)  stw_le_p(g2h(taddr), X)
# define qemu_st_lel(X)  stl_le_p(g2h(taddr), X)
# define qemu_st_leq(X)  stq_le_p(g2h(taddr), X)
# define qemu_st_bew(X)  stw_be_p(g2h(taddr), X)
# define qemu_st_bel(X)  stl_be_p(g2h(taddr), X)
# define qemu_st_beq(X)  stq_be_p(g2h(taddr), X)
#endif

/* Interpret pseudo code in tb. */
uintptr_t tcg_qemu_tb_exec(CPUArchState *env, uint8_t *tb_ptr)
{
    long tcg_temps[CPU_TEMP_BUF_NLONGS];
    uintptr_t sp_value = (uintptr_t)(tcg_temps + CPU_TEMP_BUF_NLONGS);
    uintptr_t next_tb = 0;

    tci_reg[TCG_AREG0] = (tcg_target_ulong)env;
    tci_reg[TCG_REG_CALL_STACK] = sp_value;
    assert(tb_ptr);

    for (;;) {
        TCGOpcode opc = tb_ptr[0];
#if !defined(NDEBUG)
        uint8_t op_size = tb_ptr[1];
        uint8_t *old_code_ptr = tb_ptr;
#endif
        tcg_target_ulong t0;
        tcg_target_ulong t1;
        tcg_target_ulong t2;
        DataTag t0_tag, t1_tag, t2_tag;
        tcg_target_ulong label;
        TCGCond condition;
        target_ulong taddr;
        uint8_t tmp8;
        uint16_t tmp16;
        uint32_t tmp32;
        uint64_t tmp64;
        DataTag tmp32_tag, tmp64_tag;
#if TCG_TARGET_REG_BITS == 32
        uint64_t v64;
        DataTag v64_tag;
#endif
        TCGMemOp memop;

#if defined(GETPC)
        tci_tb_ptr = (uintptr_t)tb_ptr;
#endif

        /* Skip opcode and size entry. */
        tb_ptr += 2;

        switch (opc) {
        case INDEX_op_call:
            t0 = tci_read_ri(&tb_ptr, NULL);
            helper_result_tag = 0;
#if TCG_TARGET_REG_BITS == 32
            tmp64 = ((helper_function)t0)(tci_read_reg(TCG_REG_R0, NULL),
                                          tci_read_reg(TCG_REG_R1, NULL),
                                          tci_read_reg(TCG_REG_R2, NULL),
                                          tci_read_reg(TCG_REG_R3, NULL),
                                          tci_read_reg(TCG_REG_R5, NULL),
                                          tci_read_reg(TCG_REG_R6, NULL),
                                          tci_read_reg(TCG_REG_R7, NULL),
                                          tci_read_reg(TCG_REG_R8, NULL),
                                          tci_read_reg(TCG_REG_R9, NULL),
                                          tci_read_reg(TCG_REG_R10, NULL));
            tci_write_reg(TCG_REG_R0, tmp64, helper_result_tag);
            tci_write_reg(TCG_REG_R1, tmp64 >> 32, helper_result_tag);
#else
            tmp64 = ((helper_function)t0)(tci_read_reg(TCG_REG_R0, NULL),
                                          tci_read_reg(TCG_REG_R1, NULL),
                                          tci_read_reg(TCG_REG_R2, NULL),
                                          tci_read_reg(TCG_REG_R3, NULL),
                                          tci_read_reg(TCG_REG_R5, NULL));
            tci_write_reg(TCG_REG_R0, tmp64, helper_result_tag);
#endif
            break;
        case INDEX_op_br:
            label = tci_read_label(&tb_ptr);
            assert(tb_ptr == old_code_ptr + op_size);
            tb_ptr = (uint8_t *)label;
            continue;
        case INDEX_op_setcond_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_r32(&tb_ptr, &t1_tag);
            t2 = tci_read_ri32(&tb_ptr, &t2_tag);
            condition = *tb_ptr++;
            tci_write_reg32(t0, tci_compare32(t1, t2, condition), combine_tags(t1_tag, t2_tag));
            break;
#if TCG_TARGET_REG_BITS == 32
        case INDEX_op_setcond2_i32:
            t0 = *tb_ptr++;
            tmp64 = tci_read_r64(&tb_ptr, &tmp64_tag);
            v64 = tci_read_ri64(&tb_ptr, &v64_tag);
            condition = *tb_ptr++;
            tci_write_reg32(t0, tci_compare64(tmp64, v64, condition), combine_tags(tmp64_tag, v64_tag));
            break;
#elif TCG_TARGET_REG_BITS == 64
        case INDEX_op_setcond_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_r64(&tb_ptr, &t1_tag);
            t2 = tci_read_ri64(&tb_ptr, &t2_tag);
            condition = *tb_ptr++;
            tci_write_reg64(t0, tci_compare64(t1, t2, condition), combine_tags(t1_tag, t2_tag));
            break;
#endif
        case INDEX_op_mov_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_r32(&tb_ptr, &t1_tag);
            tci_write_reg32(t0, t1, t1_tag);
            break;
        case INDEX_op_movi_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_i32(&tb_ptr);
            tci_write_reg32(t0, t1, 0);
            break;

            /* Load/store operations (32 bit). */

        case INDEX_op_ld8u_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_r(&tb_ptr, NULL);
            t2 = tci_read_s32(&tb_ptr);
            if (t1 == (tcg_target_ulong)env)
                t1_tag = read_env_tag(t2, 1);
            else
                t1_tag = 0;
            tci_write_reg8(t0, *(uint8_t *)(t1 + t2), t1_tag);
            break;
        case INDEX_op_ld8s_i32:
        case INDEX_op_ld16u_i32:
            TODO();
            break;
        case INDEX_op_ld16s_i32:
            TODO();
            break;
        case INDEX_op_ld_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_r(&tb_ptr, NULL);
            t2 = tci_read_s32(&tb_ptr);
            if (t1 == (tcg_target_ulong)env)
                t1_tag = read_env_tag(t2, 4);
            else
                t1_tag = 0;
            tci_write_reg32(t0, *(uint32_t *)(t1 + t2), t1_tag);
            break;
        case INDEX_op_st8_i32:
            t0 = tci_read_r8(&tb_ptr, &t0_tag);
            t1 = tci_read_r(&tb_ptr, NULL);
            t2 = tci_read_s32(&tb_ptr);
            *(uint8_t *)(t1 + t2) = t0;
            if (t1 == (tcg_target_ulong)env)
                write_env_tag(env, t2, 1, t0_tag);
            break;
        case INDEX_op_st16_i32:
            t0 = tci_read_r16(&tb_ptr, &t0_tag);
            t1 = tci_read_r(&tb_ptr, NULL);
            t2 = tci_read_s32(&tb_ptr);
            *(uint16_t *)(t1 + t2) = t0;
            if (t1 == (tcg_target_ulong)env)
                write_env_tag(env, t2, 2, t0_tag);
            break;
        case INDEX_op_st_i32:
            t0 = tci_read_r32(&tb_ptr, &t0_tag);
            t1 = tci_read_r(&tb_ptr, NULL);
            t2 = tci_read_s32(&tb_ptr);
            assert(t1 != sp_value || (int32_t)t2 < 0);
            *(uint32_t *)(t1 + t2) = t0;
            if (t1 == (tcg_target_ulong)env)
                write_env_tag(env, t2, 4, t0_tag);
            break;

            /* Arithmetic operations (32 bit). */

        case INDEX_op_add_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_ri32(&tb_ptr, &t1_tag);
            t2 = tci_read_ri32(&tb_ptr, &t2_tag);
            tci_write_reg32(t0, t1 + t2, combine_tags(t1_tag, t2_tag));
            break;
        case INDEX_op_sub_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_ri32(&tb_ptr, &t1_tag);
            t2 = tci_read_ri32(&tb_ptr, &t2_tag);
            tci_write_reg32(t0, t1 - t2, combine_tags(t1_tag, t2_tag));
            break;
        case INDEX_op_mul_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_ri32(&tb_ptr, &t1_tag);
            t2 = tci_read_ri32(&tb_ptr, &t2_tag);
            tci_write_reg32(t0, t1 * t2, combine_tags(t1_tag, t2_tag));
            break;
#if TCG_TARGET_HAS_div_i32
        case INDEX_op_div_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_ri32(&tb_ptr, &t1_tag);
            t2 = tci_read_ri32(&tb_ptr, &t2_tag);
            tci_write_reg32(t0, (int32_t)t1 / (int32_t)t2, combine_tags(t1_tag, t2_tag));
            break;
        case INDEX_op_divu_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_ri32(&tb_ptr, &t1_tag);
            t2 = tci_read_ri32(&tb_ptr, &t2_tag);
            tci_write_reg32(t0, t1 / t2, combine_tags(t1_tag, t2_tag));
            break;
        case INDEX_op_rem_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_ri32(&tb_ptr, &t1_tag);
            t2 = tci_read_ri32(&tb_ptr, &t2_tag);
            tci_write_reg32(t0, (int32_t)t1 % (int32_t)t2, combine_tags(t1_tag, t2_tag));
            break;
        case INDEX_op_remu_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_ri32(&tb_ptr, &t1_tag);
            t2 = tci_read_ri32(&tb_ptr, &t2_tag);
            tci_write_reg32(t0, t1 % t2, combine_tags(t1_tag, t2_tag));
            break;
#elif TCG_TARGET_HAS_div2_i32
        case INDEX_op_div2_i32:
        case INDEX_op_divu2_i32:
            TODO();
            break;
#endif
        case INDEX_op_and_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_ri32(&tb_ptr, &t1_tag);
            t2 = tci_read_ri32(&tb_ptr, &t2_tag);
            tci_write_reg32(t0, t1 & t2, combine_tags(t1_tag, t2_tag));
            break;
        case INDEX_op_or_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_ri32(&tb_ptr, &t1_tag);
            t2 = tci_read_ri32(&tb_ptr, &t2_tag);
            tci_write_reg32(t0, t1 | t2, combine_tags(t1_tag, t2_tag));
            break;
        case INDEX_op_xor_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_ri32(&tb_ptr, &t1_tag);
            t2 = tci_read_ri32(&tb_ptr, &t2_tag);
            tci_write_reg32(t0, t1 ^ t2, combine_tags(t1_tag, t2_tag));
            break;

            /* Shift/rotate operations (32 bit). */

        case INDEX_op_shl_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_ri32(&tb_ptr, &t1_tag);
            t2 = tci_read_ri32(&tb_ptr, &t2_tag);
            tci_write_reg32(t0, t1 << (t2 & 31), combine_tags(t1_tag, t2_tag));
            break;
        case INDEX_op_shr_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_ri32(&tb_ptr, &t1_tag);
            t2 = tci_read_ri32(&tb_ptr, &t2_tag);
            tci_write_reg32(t0, t1 >> (t2 & 31), combine_tags(t1_tag, t2_tag));
            break;
        case INDEX_op_sar_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_ri32(&tb_ptr, &t1_tag);
            t2 = tci_read_ri32(&tb_ptr, &t2_tag);
            tci_write_reg32(t0, ((int32_t)t1 >> (t2 & 31)), combine_tags(t1_tag, t2_tag));
            break;
#if TCG_TARGET_HAS_rot_i32
        case INDEX_op_rotl_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_ri32(&tb_ptr, &t1_tag);
            t2 = tci_read_ri32(&tb_ptr, &t2_tag);
            tci_write_reg32(t0, rol32(t1, t2 & 31), combine_tags(t1_tag, t2_tag));
            break;
        case INDEX_op_rotr_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_ri32(&tb_ptr, &t1_tag);
            t2 = tci_read_ri32(&tb_ptr, &t2_tag);
            tci_write_reg32(t0, ror32(t1, t2 & 31), combine_tags(t1_tag, t2_tag));
            break;
#endif
#if TCG_TARGET_HAS_deposit_i32
        case INDEX_op_deposit_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_r32(&tb_ptr, &t1_tag);
            t2 = tci_read_r32(&tb_ptr, &t2_tag);
            tmp16 = *tb_ptr++;
            tmp8 = *tb_ptr++;
            tmp32 = (((1 << tmp8) - 1) << tmp16);
            if ((t1_tag == 0) && (tmp16 == 0) && ((t1 & ~tmp32) == 0))
                tmp32_tag = t2_tag;
            else
                tmp32_tag = combine_tags(t1_tag, t2_tag);
            tci_write_reg32(t0, (t1 & ~tmp32) | ((t2 << tmp16) & tmp32), tmp32_tag);
            break;
#endif
        case INDEX_op_brcond_i32:
            t0 = tci_read_r32(&tb_ptr, &t0_tag);
            t1 = tci_read_ri32(&tb_ptr, &t1_tag);
            condition = *tb_ptr++;
            label = tci_read_label(&tb_ptr);
            if (tci_compare32(t0, t1, condition)) {
                assert(tb_ptr == old_code_ptr + op_size);
                tb_ptr = (uint8_t *)label;
                continue;
            }
            break;
#if TCG_TARGET_REG_BITS == 32
        case INDEX_op_add2_i32:
            t0 = *tb_ptr++;
            t1 = *tb_ptr++;
            tmp64 = tci_read_r64(&tb_ptr, &t0_tag);
            tmp64 += tci_read_r64(&tb_ptr, &t1_tag);
            tci_write_reg64(t1, t0, tmp64, combine_tags(t0_tag, t1_tag));
            break;
        case INDEX_op_sub2_i32:
            t0 = *tb_ptr++;
            t1 = *tb_ptr++;
            tmp64 = tci_read_r64(&tb_ptr, &t0_tag);
            tmp64 -= tci_read_r64(&tb_ptr, &t1_tag);
            tci_write_reg64(t1, t0, tmp64, combine_tags(t0_tag, t1_tag));
            break;
        case INDEX_op_brcond2_i32:
            tmp64 = tci_read_r64(&tb_ptr, &tmp64_tag);
            v64 = tci_read_ri64(&tb_ptr, &v64_tag);
            condition = *tb_ptr++;
            label = tci_read_label(&tb_ptr);
            if (tci_compare64(tmp64, v64, condition)) {
                assert(tb_ptr == old_code_ptr + op_size);
                tb_ptr = (uint8_t *)label;
                continue;
            }
            break;
        case INDEX_op_mulu2_i32:
            t0 = *tb_ptr++;
            t1 = *tb_ptr++;
            t2 = tci_read_r32(&tb_ptr, &t2_tag);
            tmp64 = tci_read_r32(&tb_ptr, &tmp64_tag);
            tci_write_reg64(t1, t0, t2 * tmp64, combine_tags(t2_tag, tmp64_tag));
            break;
#endif /* TCG_TARGET_REG_BITS == 32 */
#if TCG_TARGET_HAS_ext8s_i32
        case INDEX_op_ext8s_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_r8s(&tb_ptr, &t1_tag);
            tci_write_reg32(t0, t1, t1_tag);
            break;
#endif
#if TCG_TARGET_HAS_ext16s_i32
        case INDEX_op_ext16s_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_r16s(&tb_ptr, &t1_tag);
            tci_write_reg32(t0, t1, t1_tag);
            break;
#endif
#if TCG_TARGET_HAS_ext8u_i32
        case INDEX_op_ext8u_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_r8(&tb_ptr, &t1_tag);
            tci_write_reg32(t0, t1, t1_tag);
            break;
#endif
#if TCG_TARGET_HAS_ext16u_i32
        case INDEX_op_ext16u_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_r16(&tb_ptr, &t1_tag);
            tci_write_reg32(t0, t1, t1_tag);
            break;
#endif
#if TCG_TARGET_HAS_bswap16_i32
        case INDEX_op_bswap16_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_r16(&tb_ptr, &t1_tag);
            tci_write_reg32(t0, bswap16(t1), t1_tag);
            break;
#endif
#if TCG_TARGET_HAS_bswap32_i32
        case INDEX_op_bswap32_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_r32(&tb_ptr, &t1_tag);
            tci_write_reg32(t0, bswap32(t1), t1_tag);
            break;
#endif
#if TCG_TARGET_HAS_not_i32
        case INDEX_op_not_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_r32(&tb_ptr, &t1_tag);
            tci_write_reg32(t0, ~t1, combine_tags(t1_tag, t1_tag));
            break;
#endif
#if TCG_TARGET_HAS_neg_i32
        case INDEX_op_neg_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_r32(&tb_ptr, &t1_tag);
            tci_write_reg32(t0, -t1, combine_tags(t1_tag, t1_tag));
            break;
#endif
#if TCG_TARGET_REG_BITS == 64
        case INDEX_op_mov_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_r64(&tb_ptr, &t1_tag);
            tci_write_reg64(t0, t1, t1_tag);
            break;
        case INDEX_op_movi_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_i64(&tb_ptr);
            tci_write_reg64(t0, t1, 0);
            break;

            /* Load/store operations (64 bit). */

        case INDEX_op_ld8u_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_r(&tb_ptr, NULL);
            t2 = tci_read_s32(&tb_ptr);
            if (t1 == (tcg_target_ulong)env)
                t1_tag = read_env_tag(t2, 1);
            else
                t1_tag = 0;
            tci_write_reg8(t0, *(uint8_t *)(t1 + t2), t1_tag);
            break;
        case INDEX_op_ld8s_i64:
        case INDEX_op_ld16u_i64:
        case INDEX_op_ld16s_i64:
            TODO();
            break;
        case INDEX_op_ld32u_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_r(&tb_ptr, NULL);
            t2 = tci_read_s32(&tb_ptr);
            if (t1 == (tcg_target_ulong)env)
                t1_tag = read_env_tag(t2, 4);
            else
                t1_tag = 0;
            tci_write_reg32(t0, *(uint32_t *)(t1 + t2), t1_tag);
            break;
        case INDEX_op_ld32s_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_r(&tb_ptr, NULL);
            t2 = tci_read_s32(&tb_ptr);
            if (t1 == (tcg_target_ulong)env)
                t1_tag = read_env_tag(t2, 4);
            else
                t1_tag = 0;
            tci_write_reg32s(t0, *(int32_t *)(t1 + t2), t1_tag);
            break;
        case INDEX_op_ld_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_r(&tb_ptr, NULL);
            t2 = tci_read_s32(&tb_ptr);
            if (t1 == (tcg_target_ulong)env)
                t1_tag = read_env_tag(t2, 8);
            else
                t1_tag = 0;
            tci_write_reg64(t0, *(uint64_t *)(t1 + t2), t1_tag);
            break;
        case INDEX_op_st8_i64:
            t0 = tci_read_r8(&tb_ptr, &t0_tag);
            t1 = tci_read_r(&tb_ptr, NULL);
            t2 = tci_read_s32(&tb_ptr);
            *(uint8_t *)(t1 + t2) = t0;
            if (t1 == (tcg_target_ulong)env)
                write_env_tag(env, t2, 1, t0_tag);
            break;
        case INDEX_op_st16_i64:
            t0 = tci_read_r16(&tb_ptr, &t0_tag);
            t1 = tci_read_r(&tb_ptr, NULL);
            t2 = tci_read_s32(&tb_ptr);
            *(uint16_t *)(t1 + t2) = t0;
            if (t1 == (tcg_target_ulong)env)
                write_env_tag(env, t2, 2, t0_tag);
            break;
        case INDEX_op_st32_i64:
            t0 = tci_read_r32(&tb_ptr, &t0_tag);
            t1 = tci_read_r(&tb_ptr, NULL);
            t2 = tci_read_s32(&tb_ptr);
            *(uint32_t *)(t1 + t2) = t0;
            if (t1 == (tcg_target_ulong)env)
                write_env_tag(env, t2, 4, t0_tag);
            break;
        case INDEX_op_st_i64:
            t0 = tci_read_r64(&tb_ptr, &t0_tag);
            t1 = tci_read_r(&tb_ptr, NULL);
            t2 = tci_read_s32(&tb_ptr);
            assert(t1 != sp_value || (int32_t)t2 < 0);
            *(uint64_t *)(t1 + t2) = t0;
            if (t1 == (tcg_target_ulong)env)
                write_env_tag(env, t2, 8, t0_tag);
            break;

            /* Arithmetic operations (64 bit). */

        case INDEX_op_add_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_ri64(&tb_ptr, &t1_tag);
            t2 = tci_read_ri64(&tb_ptr, &t2_tag);
            tci_write_reg64(t0, t1 + t2, combine_tags(t1_tag, t2_tag));
            break;
        case INDEX_op_sub_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_ri64(&tb_ptr, &t1_tag);
            t2 = tci_read_ri64(&tb_ptr, &t2_tag);
            tci_write_reg64(t0, t1 - t2, combine_tags(t1_tag, t2_tag));
            break;
        case INDEX_op_mul_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_ri64(&tb_ptr, &t1_tag);
            t2 = tci_read_ri64(&tb_ptr, &t2_tag);
            tci_write_reg64(t0, t1 * t2, combine_tags(t1_tag, t2_tag));
            break;
#if TCG_TARGET_HAS_div_i64
        case INDEX_op_div_i64:
        case INDEX_op_divu_i64:
        case INDEX_op_rem_i64:
        case INDEX_op_remu_i64:
            TODO();
            break;
#elif TCG_TARGET_HAS_div2_i64
        case INDEX_op_div2_i64:
        case INDEX_op_divu2_i64:
            TODO();
            break;
#endif
        case INDEX_op_and_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_ri64(&tb_ptr, &t1_tag);
            t2 = tci_read_ri64(&tb_ptr, &t2_tag);
            tci_write_reg64(t0, t1 & t2, combine_tags(t1_tag, t2_tag));
            break;
        case INDEX_op_or_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_ri64(&tb_ptr, &t1_tag);
            t2 = tci_read_ri64(&tb_ptr, &t2_tag);
            tci_write_reg64(t0, t1 | t2, combine_tags(t1_tag, t2_tag));
            break;
        case INDEX_op_xor_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_ri64(&tb_ptr, &t1_tag);
            t2 = tci_read_ri64(&tb_ptr, &t2_tag);
            tci_write_reg64(t0, t1 ^ t2, combine_tags(t1_tag, t2_tag));
            break;

            /* Shift/rotate operations (64 bit). */

        case INDEX_op_shl_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_ri64(&tb_ptr, &t1_tag);
            t2 = tci_read_ri64(&tb_ptr, &t2_tag);
            tci_write_reg64(t0, t1 << (t2 & 63), combine_tags(t1_tag, t2_tag));
            break;
        case INDEX_op_shr_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_ri64(&tb_ptr, &t1_tag);
            t2 = tci_read_ri64(&tb_ptr, &t2_tag);
            tci_write_reg64(t0, t1 >> (t2 & 63), combine_tags(t1_tag, t2_tag));
            break;
        case INDEX_op_sar_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_ri64(&tb_ptr, &t1_tag);
            t2 = tci_read_ri64(&tb_ptr, &t2_tag);
            tci_write_reg64(t0, ((int64_t)t1 >> (t2 & 63)), combine_tags(t1_tag, t2_tag));
            break;
#if TCG_TARGET_HAS_rot_i64
        case INDEX_op_rotl_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_ri64(&tb_ptr, &t1_tag);
            t2 = tci_read_ri64(&tb_ptr, &t2_tag);
            tci_write_reg64(t0, rol64(t1, t2 & 63), combine_tags(t1_tag, t2_tag));
            break;
        case INDEX_op_rotr_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_ri64(&tb_ptr, &t1_tag);
            t2 = tci_read_ri64(&tb_ptr, &t2_tag);
            tci_write_reg64(t0, ror64(t1, t2 & 63), combine_tags(t1_tag, t2_tag));
            break;
#endif
#if TCG_TARGET_HAS_deposit_i64
        case INDEX_op_deposit_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_r64(&tb_ptr, &t1_tag);
            t2 = tci_read_r64(&tb_ptr, &t2_tag);
            tmp16 = *tb_ptr++;
            tmp8 = *tb_ptr++;
            tmp64 = (((1ULL << tmp8) - 1) << tmp16);
            if ((t1_tag == 0) && (tmp16 == 0) && ((t1 & ~tmp64) == 0))
                tmp64_tag = t2_tag;
            else
                tmp64_tag = combine_tags(t1_tag, t2_tag);
            tci_write_reg64(t0, (t1 & ~tmp64) | ((t2 << tmp16) & tmp64), tmp64_tag);
            break;
#endif
        case INDEX_op_brcond_i64:
            t0 = tci_read_r64(&tb_ptr, &t0_tag);
            t1 = tci_read_ri64(&tb_ptr, &t1_tag);
            condition = *tb_ptr++;
            label = tci_read_label(&tb_ptr);
            if (tci_compare64(t0, t1, condition)) {
                assert(tb_ptr == old_code_ptr + op_size);
                tb_ptr = (uint8_t *)label;
                continue;
            }
            break;
#if TCG_TARGET_HAS_ext8u_i64
        case INDEX_op_ext8u_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_r8(&tb_ptr, &t1_tag);
            tci_write_reg64(t0, t1, t1_tag);
            break;
#endif
#if TCG_TARGET_HAS_ext8s_i64
        case INDEX_op_ext8s_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_r8s(&tb_ptr, &t1_tag);
            tci_write_reg64(t0, t1, t1_tag);
            break;
#endif
#if TCG_TARGET_HAS_ext16s_i64
        case INDEX_op_ext16s_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_r16s(&tb_ptr, &t1_tag);
            tci_write_reg64(t0, t1, t1_tag);
            break;
#endif
#if TCG_TARGET_HAS_ext16u_i64
        case INDEX_op_ext16u_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_r16(&tb_ptr, &t1_tag);
            tci_write_reg64(t0, t1, t1_tag);
            break;
#endif
#if TCG_TARGET_HAS_ext32s_i64
        case INDEX_op_ext32s_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_r32s(&tb_ptr, &t1_tag);
            tci_write_reg64(t0, t1, t1_tag);
            break;
#endif
#if TCG_TARGET_HAS_ext32u_i64
        case INDEX_op_ext32u_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_r32(&tb_ptr, &t1_tag);
            tci_write_reg64(t0, t1, t1_tag);
            break;
#endif
#if TCG_TARGET_HAS_bswap16_i64
        case INDEX_op_bswap16_i64:
            TODO();
            t0 = *tb_ptr++;
            t1 = tci_read_r16(&tb_ptr, &t1_tag);
            tci_write_reg64(t0, bswap16(t1), t1_tag);
            break;
#endif
#if TCG_TARGET_HAS_bswap32_i64
        case INDEX_op_bswap32_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_r32(&tb_ptr, &t1_tag);
            tci_write_reg64(t0, bswap32(t1), t1_tag);
            break;
#endif
#if TCG_TARGET_HAS_bswap64_i64
        case INDEX_op_bswap64_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_r64(&tb_ptr, &t1_tag);
            tci_write_reg64(t0, bswap64(t1), t1_tag);
            break;
#endif
#if TCG_TARGET_HAS_not_i64
        case INDEX_op_not_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_r64(&tb_ptr, &t1_tag);
            tci_write_reg64(t0, ~t1, combine_tags(t1_tag, t1_tag));
            break;
#endif
#if TCG_TARGET_HAS_neg_i64
        case INDEX_op_neg_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_r64(&tb_ptr, &t1_tag);
            tci_write_reg64(t0, -t1, combine_tags(t1_tag, t1_tag));
            break;
#endif
#endif /* TCG_TARGET_REG_BITS == 64 */

            /* QEMU specific operations. */

#if TARGET_LONG_BITS > TCG_TARGET_REG_BITS
        case INDEX_op_debug_insn_start:
            TODO();
            break;
#else
        case INDEX_op_debug_insn_start:
            TODO();
            break;
#endif
        case INDEX_op_exit_tb:
            next_tb = *(uint64_t *)tb_ptr;
            goto exit;
            break;
        case INDEX_op_goto_tb:
            t0 = tci_read_i32(&tb_ptr);
            assert(tb_ptr == old_code_ptr + op_size);
            tb_ptr += (int32_t)t0;
            continue;
        case INDEX_op_qemu_ld_i32:
            t0 = *tb_ptr++;
            taddr = tci_read_ulong(&tb_ptr, &mem_addr_tag);
            memop = tci_read_i(&tb_ptr);
            switch (memop) {
            case MO_UB:
                tmp32 = qemu_ld_ub;
                tmp32_tag = read_mem_tag(taddr, 1);
#if defined(CONFIG_DECREE_USER)
                if (memory_trace_enabled)
                    notify_memory_read(env, taddr, 1, tmp32);
#endif
                break;
            case MO_SB:
                tmp32 = (int8_t)qemu_ld_ub;
                tmp32_tag = read_mem_tag(taddr, 1);
#if defined(CONFIG_DECREE_USER)
                if (memory_trace_enabled)
                    notify_memory_read(env, taddr, 1, tmp32);
#endif
                break;
            case MO_LEUW:
                tmp32 = qemu_ld_leuw;
                tmp32_tag = read_mem_tag(taddr, 2);
#if defined(CONFIG_DECREE_USER)
                if (memory_trace_enabled)
                    notify_memory_read(env, taddr, 2, tmp32);
#endif
                break;
            case MO_LESW:
                tmp32 = (int16_t)qemu_ld_leuw;
                tmp32_tag = read_mem_tag(taddr, 2);
#if defined(CONFIG_DECREE_USER)
                if (memory_trace_enabled)
                    notify_memory_read(env, taddr, 2, tmp32);
#endif
                break;
            case MO_LEUL:
                tmp32 = qemu_ld_leul;
                tmp32_tag = read_mem_tag(taddr, 4);
#if defined(CONFIG_DECREE_USER)
                if (memory_trace_enabled)
                    notify_memory_read(env, taddr, 4, tmp32);
#endif
                break;
            case MO_BEUW:
                tmp32 = qemu_ld_beuw;
                tmp32_tag = read_mem_tag(taddr, 2);
#if defined(CONFIG_DECREE_USER)
                if (memory_trace_enabled)
                    notify_memory_read(env, taddr, 2, tmp32);
#endif
                break;
            case MO_BESW:
                tmp32 = (int16_t)qemu_ld_beuw;
                tmp32_tag = read_mem_tag(taddr, 2);
#if defined(CONFIG_DECREE_USER)
                if (memory_trace_enabled)
                    notify_memory_read(env, taddr, 2, tmp32);
#endif
                break;
            case MO_BEUL:
                tmp32 = qemu_ld_beul;
                tmp32_tag = read_mem_tag(taddr, 4);
#if defined(CONFIG_DECREE_USER)
                if (memory_trace_enabled)
                    notify_memory_read(env, taddr, 4, tmp32);
#endif
                break;
            default:
                tcg_abort();
            }
            tci_write_reg(t0, tmp32, tmp32_tag);
            mem_addr_tag = 0;
            break;
        case INDEX_op_qemu_ld_i64:
            t0 = *tb_ptr++;
            if (TCG_TARGET_REG_BITS == 32) {
                t1 = *tb_ptr++;
            }
            taddr = tci_read_ulong(&tb_ptr, &mem_addr_tag);
            memop = tci_read_i(&tb_ptr);
            switch (memop) {
            case MO_UB:
                tmp64 = qemu_ld_ub;
                tmp64_tag = read_mem_tag(taddr, 1);
#if defined(CONFIG_DECREE_USER)
                if (memory_trace_enabled)
                    notify_memory_read(env, taddr, 1, tmp64);
#endif
                break;
            case MO_SB:
                tmp64 = (int8_t)qemu_ld_ub;
                tmp64_tag = read_mem_tag(taddr, 1);
#if defined(CONFIG_DECREE_USER)
                if (memory_trace_enabled)
                    notify_memory_read(env, taddr, 1, tmp64);
#endif
                break;
            case MO_LEUW:
                tmp64 = qemu_ld_leuw;
                tmp64_tag = read_mem_tag(taddr, 2);
#if defined(CONFIG_DECREE_USER)
                if (memory_trace_enabled)
                    notify_memory_read(env, taddr, 2, tmp64);
#endif
                break;
            case MO_LESW:
                tmp64 = (int16_t)qemu_ld_leuw;
                tmp64_tag = read_mem_tag(taddr, 2);
#if defined(CONFIG_DECREE_USER)
                if (memory_trace_enabled)
                    notify_memory_read(env, taddr, 2, tmp64);
#endif
                break;
            case MO_LEUL:
                tmp64 = qemu_ld_leul;
                tmp64_tag = read_mem_tag(taddr, 4);
#if defined(CONFIG_DECREE_USER)
                if (memory_trace_enabled)
                    notify_memory_read(env, taddr, 4, tmp64);
#endif
                break;
            case MO_LESL:
                tmp64 = (int32_t)qemu_ld_leul;
                tmp64_tag = read_mem_tag(taddr, 4);
#if defined(CONFIG_DECREE_USER)
                if (memory_trace_enabled)
                    notify_memory_read(env, taddr, 4, tmp64);
#endif
                break;
            case MO_LEQ:
                tmp64 = qemu_ld_leq;
                tmp64_tag = read_mem_tag(taddr, 8);
#if defined(CONFIG_DECREE_USER)
                if (memory_trace_enabled)
                    notify_memory_read(env, taddr, 8, tmp64);
#endif
                break;
            case MO_BEUW:
                tmp64 = qemu_ld_beuw;
                tmp64_tag = read_mem_tag(taddr, 2);
#if defined(CONFIG_DECREE_USER)
                if (memory_trace_enabled)
                    notify_memory_read(env, taddr, 2, tmp64);
#endif
                break;
            case MO_BESW:
                tmp64 = (int16_t)qemu_ld_beuw;
                tmp64_tag = read_mem_tag(taddr, 2);
#if defined(CONFIG_DECREE_USER)
                if (memory_trace_enabled)
                    notify_memory_read(env, taddr, 2, tmp64);
#endif
                break;
            case MO_BEUL:
                tmp64 = qemu_ld_beul;
                tmp64_tag = read_mem_tag(taddr, 4);
#if defined(CONFIG_DECREE_USER)
                if (memory_trace_enabled)
                    notify_memory_read(env, taddr, 4, tmp64);
#endif
                break;
            case MO_BESL:
                tmp64 = (int32_t)qemu_ld_beul;
                tmp64_tag = read_mem_tag(taddr, 4);
#if defined(CONFIG_DECREE_USER)
                if (memory_trace_enabled)
                    notify_memory_read(env, taddr, 4, tmp64);
#endif
                break;
            case MO_BEQ:
                tmp64 = qemu_ld_beq;
                tmp64_tag = read_mem_tag(taddr, 8);
#if defined(CONFIG_DECREE_USER)
                if (memory_trace_enabled)
                    notify_memory_read(env, taddr, 8, tmp64);
#endif
                break;
            default:
                tcg_abort();
            }
            tci_write_reg(t0, tmp64, tmp64_tag);
            if (TCG_TARGET_REG_BITS == 32) {
                tci_write_reg(t1, tmp64 >> 32, tmp64_tag);
            }
            mem_addr_tag = 0;
            break;
        case INDEX_op_qemu_st_i32:
            t0 = tci_read_r(&tb_ptr, &t0_tag);
            taddr = tci_read_ulong(&tb_ptr, &mem_addr_tag);
            memop = tci_read_i(&tb_ptr);
            switch (memop) {
            case MO_UB:
                qemu_st_b(t0);
                write_mem_tag(env, taddr, 1, t0_tag);
#if defined(CONFIG_DECREE_USER)
                if (memory_trace_enabled)
                    notify_memory_write(env, taddr, 1, t0);
#endif
                break;
            case MO_LEUW:
                qemu_st_lew(t0);
                write_mem_tag(env, taddr, 2, t0_tag);
#if defined(CONFIG_DECREE_USER)
                if (memory_trace_enabled)
                    notify_memory_write(env, taddr, 2, t0);
#endif
                break;
            case MO_LEUL:
                qemu_st_lel(t0);
                write_mem_tag(env, taddr, 4, t0_tag);
#if defined(CONFIG_DECREE_USER)
                if (memory_trace_enabled)
                    notify_memory_write(env, taddr, 4, t0);
#endif
                break;
            case MO_BEUW:
                qemu_st_bew(t0);
                write_mem_tag(env, taddr, 2, t0_tag);
#if defined(CONFIG_DECREE_USER)
                if (memory_trace_enabled)
                    notify_memory_write(env, taddr, 2, t0);
#endif
                break;
            case MO_BEUL:
                qemu_st_bel(t0);
                write_mem_tag(env, taddr, 4, t0_tag);
#if defined(CONFIG_DECREE_USER)
                if (memory_trace_enabled)
                    notify_memory_write(env, taddr, 4, t0);
#endif
                break;
            default:
                tcg_abort();
            }
            mem_addr_tag = 0;
            break;
        case INDEX_op_qemu_st_i64:
            tmp64 = tci_read_r64(&tb_ptr, &tmp64_tag);
            taddr = tci_read_ulong(&tb_ptr, &mem_addr_tag);
            memop = tci_read_i(&tb_ptr);
            switch (memop) {
            case MO_UB:
                qemu_st_b(tmp64);
                write_mem_tag(env, taddr, 1, tmp64_tag);
#if defined(CONFIG_DECREE_USER)
                if (memory_trace_enabled)
                    notify_memory_write(env, taddr, 1, tmp64);
#endif
                break;
            case MO_LEUW:
                qemu_st_lew(tmp64);
                write_mem_tag(env, taddr, 2, tmp64_tag);
#if defined(CONFIG_DECREE_USER)
                if (memory_trace_enabled)
                    notify_memory_write(env, taddr, 2, tmp64);
#endif
                break;
            case MO_LEUL:
                qemu_st_lel(tmp64);
                write_mem_tag(env, taddr, 4, tmp64_tag);
#if defined(CONFIG_DECREE_USER)
                if (memory_trace_enabled)
                    notify_memory_write(env, taddr, 4, tmp64);
#endif
                break;
            case MO_LEQ:
                qemu_st_leq(tmp64);
                write_mem_tag(env, taddr, 8, tmp64_tag);
#if defined(CONFIG_DECREE_USER)
                if (memory_trace_enabled)
                    notify_memory_write(env, taddr, 8, tmp64);
#endif
                break;
            case MO_BEUW:
                qemu_st_bew(tmp64);
                write_mem_tag(env, taddr, 2, tmp64_tag);
#if defined(CONFIG_DECREE_USER)
                if (memory_trace_enabled)
                    notify_memory_write(env, taddr, 2, tmp64);
#endif
                break;
            case MO_BEUL:
                qemu_st_bel(tmp64);
                write_mem_tag(env, taddr, 4, tmp64_tag);
#if defined(CONFIG_DECREE_USER)
                if (memory_trace_enabled)
                    notify_memory_write(env, taddr, 4, tmp64);
#endif
                break;
            case MO_BEQ:
                qemu_st_beq(tmp64);
                write_mem_tag(env, taddr, 8, tmp64_tag);
#if defined(CONFIG_DECREE_USER)
                if (memory_trace_enabled)
                    notify_memory_write(env, taddr, 8, tmp64);
#endif
                break;
            default:
                tcg_abort();
            }
            mem_addr_tag = 0;
            break;
        default:
            TODO();
            break;
        }
        assert(tb_ptr == old_code_ptr + op_size);
    }
exit:
    return next_tb;
}
