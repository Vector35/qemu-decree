/*
 *  qemu user main
 *
 *  Copyright (c) 2003-2008 Fabrice Bellard
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <libgen.h>

#include "qemu.h"
#include "qemu-common.h"
#include "cpu.h"
#include "tcg.h"
#include "qemu/timer.h"
#include "qemu/envlist.h"
#include "elf.h"
#include "qemu/aes.h"

int singlestep;
int gdbstub_port;
static const char *cpu_model;
unsigned long mmap_min_addr = DECREE_MMAP_MIN_ADDRESS;
#if defined(CONFIG_USE_GUEST_BASE)
unsigned long guest_base;
int have_guest_base;
#if (TARGET_LONG_BITS == 32) && (HOST_LONG_BITS == 64)
/*
 * When running 32-on-64 we should make sure we can fit all of the possible
 * guest address space into a contiguous chunk of virtual host memory.
 *
 * This way we will never overlap with our own libraries or binaries or stack
 * or anything else that QEMU maps.
 *
 * Use 4GB+4kB here to ensure that it is not possible for the guest to
 * address memory outside its address space.
 */
unsigned long reserved_va = 0x100001000L;
#else
unsigned long reserved_va;
#endif
#endif

int binary_count;
int binary_index;
int timeout = 0;
uint8_t random_seed[48];
static int valid_random_bytes = 0;
static uint8_t random_buffer[16];
static uint8_t *random_buffer_ptr = NULL;
AES_KEY random_key;

long max_recv = -1;

static char* record_replay_name = NULL;
static char* replay_playback_name[MAX_BINARIES];
static int replay_playback_count = 0;
int record_replay_flags = 0;

int fd_valid[MAX_FD];
int limit_closed_fd_ops = 0;
int closed_fd_ops = 0;

static char* analysis_output_name = NULL;

static uint8_t pov_random_seed[48];
static uint8_t negotiate_random_seed[48];
static char* pov_name = NULL;
static int is_pov = 0;
static pid_t pov_pid;
static int pov_pipes[4];
static int pov_negotiate_sockets[2];

struct shared_data *shared = NULL;

static void usage(void);

void gemu_log(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

#if defined(TARGET_I386)
int cpu_get_pic_interrupt(CPUX86State *env)
{
    return -1;
}
#endif

/***********************************************************/
/* Helper routines for implementing atomic operations.  */

/* To implement exclusive operations we force all cpus to syncronise.
   We don't require a full sync, only that no cpus are executing guest code.
   The alternative is to map target atomic ops onto host equivalents,
   which requires quite a lot of per host/target work.  */
static pthread_mutex_t cpu_list_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t exclusive_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t exclusive_cond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t exclusive_resume = PTHREAD_COND_INITIALIZER;
static int pending_cpus;

/* Wait for pending exclusive operations to complete.  The exclusive lock
   must be held.  */
static inline void exclusive_idle(void)
{
    while (pending_cpus) {
        pthread_cond_wait(&exclusive_resume, &exclusive_lock);
    }
}

/* Start an exclusive operation.
   Must only be called from outside cpu_arm_exec.   */
static inline void start_exclusive(void)
{
    CPUState *other_cpu;

    pthread_mutex_lock(&exclusive_lock);
    exclusive_idle();

    pending_cpus = 1;
    /* Make all other cpus stop executing.  */
    CPU_FOREACH(other_cpu) {
        if (other_cpu->running) {
            pending_cpus++;
            cpu_exit(other_cpu);
        }
    }
    if (pending_cpus > 1) {
        pthread_cond_wait(&exclusive_cond, &exclusive_lock);
    }
}

/* Finish an exclusive operation.  */
static inline void __attribute__((unused)) end_exclusive(void)
{
    pending_cpus = 0;
    pthread_cond_broadcast(&exclusive_resume);
    pthread_mutex_unlock(&exclusive_lock);
}

/* Wait for exclusive ops to finish, and begin cpu execution.  */
static inline void cpu_exec_start(CPUState *cpu)
{
    pthread_mutex_lock(&exclusive_lock);
    exclusive_idle();
    cpu->running = true;
    pthread_mutex_unlock(&exclusive_lock);
}

/* Mark cpu as not executing, and release pending exclusive ops.  */
static inline void cpu_exec_end(CPUState *cpu)
{
    pthread_mutex_lock(&exclusive_lock);
    cpu->running = false;
    if (pending_cpus > 1) {
        pending_cpus--;
        if (pending_cpus == 1) {
            pthread_cond_signal(&exclusive_cond);
        }
    }
    exclusive_idle();
    pthread_mutex_unlock(&exclusive_lock);
}

void cpu_list_lock(void)
{
    pthread_mutex_lock(&cpu_list_mutex);
}

void cpu_list_unlock(void)
{
    pthread_mutex_unlock(&cpu_list_mutex);
}


#ifdef TARGET_I386
/***********************************************************/
/* CPUX86 core interface */

void cpu_smm_update(CPUX86State *env)
{
}

static void retire_syscall(CPUX86State *env)
{
    InsnInstrumentation *instrument;

    if (unlikely(!QTAILQ_EMPTY(&instrumentation.insn_instrumentation))) {
        QTAILQ_FOREACH(instrument, &instrumentation.insn_instrumentation, entry) {
            /* Ignore instrumentation that does not need post-processing */
            if (!instrument->after)
                continue;

            /* Check filter before calling the callback.  We don't know which instrumentations passed
             the filter before the instruction started executing. */
            if (instrument->filter) {
                if (!instrument->filter(env, instrument->data, insn_eip, &cur_insn))
                    continue;
            }

            /* This instrumentation applies, call the after callback now */
            instrument->after(env, instrument->data, insn_eip, &cur_insn);
        }
    }

    if (is_record_or_replay())
        env->insn_retired++;
}

void cpu_loop(CPUX86State *env)
{
    CPUState *cs = CPU(x86_env_get_cpu(env));
    int trapnr;
    abi_ulong pc, orig_eax;
    target_siginfo_t info;

    for(;;) {
        if (is_replaying())
            check_for_replay_timeout(env);

        cpu_exec_start(cs);
        trapnr = cpu_x86_exec(env);
        cpu_exec_end(cs);
        switch(trapnr) {
        case 0x80:
            /* linux syscall from int $0x80 */
            while (true) {
                orig_eax = env->regs[R_EAX];
                env->regs[R_EAX] = do_syscall(env,
                                              env->regs[R_EAX],
                                              env->regs[R_EBX],
                                              env->regs[R_ECX],
                                              env->regs[R_EDX],
                                              env->regs[R_ESI],
                                              env->regs[R_EDI],
                                              env->regs[R_EBP]);
                if (env->regs[R_EAX] == TARGET_EINTR) {
                    /* Automatically restart interrupted syscalls */
                    env->regs[R_EAX] = orig_eax;
                    continue;
                }
                break;
            }
            retire_syscall(env);
            break;
        case EXCP_SYSCALL:
            info.si_signo = TARGET_SIGILL;
            info.si_errno = 0;
            info.si_code = TARGET_SI_KERNEL;
            info._sifields._sigfault._addr = 0;
            queue_signal(env, info.si_signo, &info);
            break;
        case EXCP0B_NOSEG:
        case EXCP0C_STACK:
            info.si_signo = TARGET_SIGBUS;
            info.si_errno = 0;
            info.si_code = TARGET_SI_KERNEL;
            info._sifields._sigfault._addr = 0;
            queue_signal(env, info.si_signo, &info);
            break;
        case EXCP0D_GPF:
            info.si_signo = TARGET_SIGSEGV;
            info.si_errno = 0;
            info.si_code = TARGET_SI_KERNEL;
            info._sifields._sigfault._addr = 0;
            queue_signal(env, info.si_signo, &info);
            break;
        case EXCP0E_PAGE:
            info.si_signo = TARGET_SIGSEGV;
            info.si_errno = 0;
            if (!(env->error_code & 1))
                info.si_code = TARGET_SEGV_MAPERR;
            else
                info.si_code = TARGET_SEGV_ACCERR;
            info._sifields._sigfault._addr = env->cr[2];
            queue_signal(env, info.si_signo, &info);
            break;
        case EXCP00_DIVZ:
            /* division by zero */
            info.si_signo = TARGET_SIGFPE;
            info.si_errno = 0;
            info.si_code = TARGET_FPE_INTDIV;
            info._sifields._sigfault._addr = env->eip;
            queue_signal(env, info.si_signo, &info);
            break;
        case EXCP01_DB:
        case EXCP03_INT3:
            info.si_signo = TARGET_SIGTRAP;
            info.si_errno = 0;
            if (trapnr == EXCP01_DB) {
                info.si_code = TARGET_TRAP_BRKPT;
                info._sifields._sigfault._addr = env->eip;
            } else {
                info.si_code = TARGET_SI_KERNEL;
                info._sifields._sigfault._addr = 0;
            }
            queue_signal(env, info.si_signo, &info);
            break;
        case EXCP04_INTO:
        case EXCP05_BOUND:
            info.si_signo = TARGET_SIGSEGV;
            info.si_errno = 0;
            info.si_code = TARGET_SI_KERNEL;
            info._sifields._sigfault._addr = 0;
            queue_signal(env, info.si_signo, &info);
            break;
        case EXCP06_ILLOP:
            info.si_signo = TARGET_SIGILL;
            info.si_errno = 0;
            info.si_code = TARGET_ILL_ILLOPN;
            info._sifields._sigfault._addr = env->eip;
            queue_signal(env, info.si_signo, &info);
            break;
        case EXCP_INTERRUPT:
            /* just indicate that signals should be handled asap */
            break;
        case EXCP_DEBUG:
            {
                int sig;

                sig = gdb_handlesig(cs, TARGET_SIGTRAP);
                if (sig)
                  {
                    info.si_signo = sig;
                    info.si_errno = 0;
                    info.si_code = TARGET_TRAP_BRKPT;
                    queue_signal(env, info.si_signo, &info);
                  }
            }
            break;
        default:
            pc = env->segs[R_CS].base + env->eip;
            fprintf(stderr, "qemu: 0x%08lx: unhandled CPU exception 0x%x - aborting\n",
                    (long)pc, trapnr);
            abort();
        }
        process_pending_signals(env);
    }
}
#endif

THREAD CPUState *thread_cpu;

void task_settid(TaskState *ts)
{
    if (ts->ts_tid == 0) {
        ts->ts_tid = (pid_t)syscall(SYS_gettid);
    }
}

void stop_all_tasks(void)
{
    /*
     * We trust that when using NPTL, start_exclusive()
     * handles thread stopping correctly.
     */
    start_exclusive();
}

/* Assumes contents are already zeroed.  */
void init_task_state(TaskState *ts)
{
    int i;

    ts->used = 1;
    ts->first_free = ts->sigqueue_table;
    for (i = 0; i < MAX_SIGQUEUE_SIZE - 1; i++) {
        ts->sigqueue_table[i].next = &ts->sigqueue_table[i + 1];
    }
    ts->sigqueue_table[i].next = NULL;
}

CPUArchState *cpu_copy(CPUArchState *env)
{
    CPUState *cpu = ENV_GET_CPU(env);
    CPUArchState *new_env = cpu_init(cpu_model);
    CPUState *new_cpu = ENV_GET_CPU(new_env);
    CPUBreakpoint *bp;
    CPUWatchpoint *wp;

    /* Reset non arch specific state */
    cpu_reset(new_cpu);

    memcpy(new_env, env, sizeof(CPUArchState));

    /* Clone all break/watchpoints.
       Note: Once we support ptrace with hw-debug register access, make sure
       BP_CPU break/watchpoints are handled correctly on clone. */
    QTAILQ_INIT(&cpu->breakpoints);
    QTAILQ_INIT(&cpu->watchpoints);
    QTAILQ_FOREACH(bp, &cpu->breakpoints, entry) {
        cpu_breakpoint_insert(new_cpu, bp->pc, bp->flags, NULL);
    }
    QTAILQ_FOREACH(wp, &cpu->watchpoints, entry) {
        cpu_watchpoint_insert(new_cpu, wp->vaddr, wp->len, wp->flags, NULL);
    }

    return new_env;
}

static void handle_arg_help(const char *arg)
{
    usage();
}

static void handle_arg_timeout(const char* arg)
{
    unsigned long long seconds;

    if (parse_uint_full(arg, &seconds, 0) != 0 || seconds > INT_MAX) {
        fprintf(stderr, "Invalid timeout: %s\n", arg);
        exit(1);
    }

    timeout = (int)seconds;
}

static void handle_arg_log(const char *arg)
{
    int mask;

    mask = qemu_str_to_log_mask(arg);
    if (!mask) {
        qemu_print_log_usage(stdout);
        exit(1);
    }
    qemu_set_log(mask);
}

static void handle_arg_log_filename(const char *arg)
{
    qemu_set_log_filename(arg);
}

static void handle_arg_record(const char* arg)
{
    record_replay_name = strdup(arg);
}

static void handle_arg_replay(const char* arg)
{
    if (replay_playback_count >= MAX_BINARIES) {
        fprintf(stderr, "Too many replays specified (maximum %d)\n", MAX_BINARIES);
        exit(1);
    }
    replay_playback_name[replay_playback_count++] = strdup(arg);
}

static void handle_arg_compact(const char* arg)
{
    record_replay_flags |= REPLAY_FLAG_COMPACT;
}

static void handle_arg_analyze(const char* arg)
{
    analysis_output_name = strdup(arg);
}

static void handle_arg_analysis_type(const char* arg)
{
    if (is_help_option(arg)) {
        show_available_analysis_types();
        exit(1);
    }

    add_pending_analysis(arg);
}

static void parse_randseed(uint8_t *seed, const char *arg)
{
    size_t i, j;
    int high = 1;

    memset(seed, 0, 48);

    for (i = 0, j = 0; j < 48; i++) {
        uint8_t val;
        if ((arg[i] >= '0')  && (arg[i] <= '9')) {
            val = arg[i] - '0';
        } else if ((arg[i] >= 'a') && (arg[i] <= 'f')) {
            val = arg[i] - 'a' + 10;
        } else if ((arg[i] >= 'A') && (arg[i] <= 'F')) {
            val = arg[i] - 'A' + 10;
        } else {
            fprintf(stderr, "Invalid seed number: %s\n", arg);
            exit(1);
        }

        if (high) {
            seed[j] = val << 4;
            high = 0;
        } else {
            seed[j] |= val;
            high = 1;
            j++;
        }
    }
}

static void handle_arg_randseed(const char *arg)
{
    parse_randseed(random_seed, arg);
}

static void handle_arg_pov(const char* arg)
{
    pov_name = strdup(arg);
}

static void handle_arg_pov_randseed(const char *arg)
{
    parse_randseed(pov_random_seed, arg);
}

static void handle_arg_negotiate_randseed(const char *arg)
{
    parse_randseed(negotiate_random_seed, arg);
}

static void handle_arg_maxrecv(const char* arg)
{
    unsigned long long bytes;

    if (parse_uint_full(arg, &bytes, 0) != 0 || bytes > INT_MAX) {
        fprintf(stderr, "Invalid maximum recv size: %s\n", arg);
        exit(1);
    }

    max_recv = (long)bytes;
}

static void handle_arg_gdb(const char *arg)
{
    gdbstub_port = atoi(arg);
}

static void handle_arg_cpu(const char *arg)
{
    cpu_model = strdup(arg);
    if (cpu_model == NULL || is_help_option(cpu_model)) {
        /* XXX: implement xxx_cpu_list for targets that still miss it */
#if defined(cpu_list)
        cpu_list(stdout, &fprintf);
#endif
        exit(1);
    }
}

#if defined(CONFIG_USE_GUEST_BASE)
static void handle_arg_guest_base(const char *arg)
{
    guest_base = strtol(arg, NULL, 0);
    have_guest_base = 1;
}

static void handle_arg_reserved_va(const char *arg)
{
    char *p;
    int shift = 0;
    reserved_va = strtoul(arg, &p, 0);
    switch (*p) {
    case 'k':
    case 'K':
        shift = 10;
        break;
    case 'M':
        shift = 20;
        break;
    case 'G':
        shift = 30;
        break;
    }
    if (shift) {
        unsigned long unshifted = reserved_va;
        p++;
        reserved_va <<= shift;
        if (((reserved_va >> shift) != unshifted)
#if HOST_LONG_BITS > TARGET_VIRT_ADDR_SPACE_BITS
            || (reserved_va > (1ul << TARGET_VIRT_ADDR_SPACE_BITS))
#endif
            ) {
            fprintf(stderr, "Reserved virtual address too big\n");
            exit(1);
        }
    }
    if (*p) {
        fprintf(stderr, "Unrecognised -R size suffix '%s'\n", p);
        exit(1);
    }
}
#endif

static void handle_arg_singlestep(const char *arg)
{
    singlestep = 1;
}

static void handle_arg_strace(const char *arg)
{
    do_strace = 1;
}

static void handle_arg_closeopt(const char *arg)
{
    limit_closed_fd_ops = 1;
    record_replay_flags |= REPLAY_FLAG_LIMIT_CLOSED_FD_LOOP;
}

static void handle_arg_version(const char *arg)
{
    printf("qemu-" TARGET_NAME " version " QEMU_VERSION QEMU_PKGVERSION
           ", Copyright (c) 2003-2008 Fabrice Bellard\n");
    exit(0);
}

struct qemu_argument {
    const char *argv;
    const char *env;
    bool has_arg;
    void (*handle_opt)(const char *arg);
    const char *example;
    const char *help;
};

static const struct qemu_argument arg_table[] = {
    {"h",          "",                 false, handle_arg_help,
     "",           "print this help"},
    {"g",          "QEMU_GDB",         true,  handle_arg_gdb,
     "port",       "wait gdb connection to 'port'"},
    {"t",          "QEMU_TIMEOUT",     true,  handle_arg_timeout,
     "seconds",    "Maximum run time for the process"},
    {"cpu",        "QEMU_CPU",         true,  handle_arg_cpu,
     "model",      "select CPU (-cpu help for list)"},
#if defined(CONFIG_USE_GUEST_BASE)
    {"B",          "QEMU_GUEST_BASE",  true,  handle_arg_guest_base,
     "address",    "set guest_base address to 'address'"},
    {"R",          "QEMU_RESERVED_VA", true,  handle_arg_reserved_va,
     "size",       "reserve 'size' bytes for guest virtual address space"},
#endif
    {"d",          "QEMU_LOG",         true,  handle_arg_log,
     "item[,...]", "enable logging of specified items "
     "(use '-d help' for a list of items)"},
    {"D",          "QEMU_LOG_FILENAME", true, handle_arg_log_filename,
     "logfile",     "write logs to 'logfile' (default stderr)"},
    {"record",     "QEMU_RECORD",      true,  handle_arg_record,
     "name",       "Record this execution for later replay"},
    {"replay",     "QEMU_REPLAY",      true,  handle_arg_replay,
     "name",       "Replay a recorded execution"},
    {"compact",    "QEMU_RECORD_COMPACT", false,  handle_arg_compact,
     "",           "Leave out validation information for smaller replay"},
    {"analyze",    "QEMU_ANALYZE",     true,  handle_arg_analyze,
     "name",       "Generate an analysis output file"},
    {"A",          "QEMU_ANALYSIS_TYPE", true, handle_arg_analysis_type,
     "type[,args]", "Activate an analysis, multiple allowed (-A help for list)"},
    {"singlestep", "QEMU_SINGLESTEP",  false, handle_arg_singlestep,
     "",           "run in singlestep mode"},
    {"strace",     "QEMU_STRACE",      false, handle_arg_strace,
     "",           "log system calls"},
    {"seed",       "QEMU_RAND_SEED",   true,  handle_arg_randseed,
     "",           "Seed for pseudo-random number generator in CB"},
    {"maxrecv",    "QEMU_MAX_RECV",    true,  handle_arg_maxrecv,
     "",           "Maximum bytes to receive in one call (for debug)"},
    {"closeopt",   "QEMU_CLOSE_OPT",   false, handle_arg_closeopt,
     "",           "Limit reads/writes to closed handles"},
    {"pov",        "QEMU_POV",         true,  handle_arg_pov,
     "",           "Exceute PoV binary"},
    {"povseed",    "QEMU_POV_RAND_SEED", true,  handle_arg_pov_randseed,
     "",           "Seed for pseudo-random number generator in PoV"},
    {"negseed",    "QEMU_NEG_RAND_SEED", true,  handle_arg_negotiate_randseed,
     "",           "Seed for pseudo-random number generator in PoV negotiation"},
    {"version",    "QEMU_VERSION",     false, handle_arg_version,
     "",           "display version information and exit"},
    {NULL, NULL, false, NULL, NULL, NULL}
};

static void usage(void)
{
    const struct qemu_argument *arginfo;
    int maxarglen;
    int maxenvlen;

    printf("usage: qemu-decree [options] binaries [...]\n"
           "Cyber Grand Challenge DECREE emulator (compiled for " TARGET_NAME " emulation)\n"
           "\n"
           "Options and associated environment variables:\n"
           "\n");

    /* Calculate column widths. We must always have at least enough space
     * for the column header.
     */
    maxarglen = strlen("Argument");
    maxenvlen = strlen("Env-variable");

    for (arginfo = arg_table; arginfo->handle_opt != NULL; arginfo++) {
        int arglen = strlen(arginfo->argv);
        if (arginfo->has_arg) {
            arglen += strlen(arginfo->example) + 1;
        }
        if (strlen(arginfo->env) > maxenvlen) {
            maxenvlen = strlen(arginfo->env);
        }
        if (arglen > maxarglen) {
            maxarglen = arglen;
        }
    }

    printf("%-*s %-*s Description\n", maxarglen+1, "Argument",
            maxenvlen, "Env-variable");

    for (arginfo = arg_table; arginfo->handle_opt != NULL; arginfo++) {
        if (arginfo->has_arg) {
            printf("-%s %-*s %-*s %s\n", arginfo->argv,
                   (int)(maxarglen - strlen(arginfo->argv) - 1),
                   arginfo->example, maxenvlen, arginfo->env, arginfo->help);
        } else {
            printf("-%-*s %-*s %s\n", maxarglen, arginfo->argv,
                    maxenvlen, arginfo->env,
                    arginfo->help);
        }
    }

    exit(1);
}

static int parse_args(int argc, char **argv)
{
    const char *r;
    int optind;
    const struct qemu_argument *arginfo;

    for (arginfo = arg_table; arginfo->handle_opt != NULL; arginfo++) {
        if (arginfo->env == NULL) {
            continue;
        }

        r = getenv(arginfo->env);
        if (r != NULL) {
            arginfo->handle_opt(r);
        }
    }

    optind = 1;
    for (;;) {
        if (optind >= argc) {
            break;
        }
        r = argv[optind];
        if (r[0] != '-') {
            break;
        }
        optind++;
        r++;
        if (!strcmp(r, "-")) {
            break;
        }

        for (arginfo = arg_table; arginfo->handle_opt != NULL; arginfo++) {
            if (!strcmp(r, arginfo->argv)) {
                if (arginfo->has_arg) {
                    if (optind >= argc) {
                        usage();
                    }
                    arginfo->handle_opt(argv[optind]);
                    optind++;
                } else {
                    arginfo->handle_opt(NULL);
                }
                break;
            }
        }

        /* no option matched the current argv */
        if (arginfo->handle_opt == NULL) {
            usage();
        }
    }

    if (optind >= argc) {
        usage();
    }

    return optind;
}

static void open_and_load_file(const char* filename,
                               struct target_pt_regs * regs, struct image_info *info,
                               struct linux_binprm *bprm)
{
    int execfd;
    int ret;

    execfd = open(filename, O_RDONLY);
    if (execfd < 0) {
        printf("Error while loading %s: %s\n", filename, strerror(errno));
        _exit(1);
    }

    ret = loader_exec(execfd, filename, regs, info, bprm);
    if (ret != 0) {
        printf("Error while loading %s: %s\n", filename, strerror(-ret));
        _exit(1);
    }

    close(execfd);
}

static void sigchild_handler(int sig)
{
}

int is_valid_guest_fd(int fd)
{
    /* Check file descriptor on guest access to make sure it is one it should be accessing */
    if (fd < 0)
        return 0;
    if (fd <= 2) /* stdin/stdout/stderr are always valid */
        return 1;
    if (is_pov && (fd == 3)) /* 3 is negotiation socket in PoV */
        return 1;
    if (binary_count <= 1) /* If single binary, only stdin/stdout/stderr are valid */
        return 0;
    if (fd <= (4 + 2 * binary_count)) /* For multi-binary, allow socket pairs */
        return 1;
    return 0;
}

static void fill_random_buffer(void)
{
    uint8_t i[16];
    uint8_t iXorV[16];
    uint8_t v[16];
    size_t n;

    AES_encrypt(&random_seed[32], i, &random_key);

    for (n = 0; n < 16; n++)
        iXorV[n] = i[n] ^ random_seed[n];
    AES_encrypt(iXorV, random_buffer, &random_key);

    for (n = 0; n < 16; n++)
        v[n] = random_buffer[n] ^ i[n];
    AES_encrypt(v, random_seed, &random_key);

    for (n = 47; n >= 32; n--) {
        random_seed[n]++;
        if (random_seed[n] != 0)
            break;
    }

    random_buffer_ptr = random_buffer;
    valid_random_bytes = 16;
}

void get_random_bytes(uint8_t* out, size_t len)
{
    while (len > 0) {
        if (valid_random_bytes == 0)
            fill_random_buffer();

        size_t block = len;
        if (block > valid_random_bytes)
            block = valid_random_bytes;

        memcpy(out, random_buffer_ptr, block);
        valid_random_bytes -= block;
        random_buffer_ptr += block;
        out += block;
        len -= block;
    }
}

static int read_all(int s, void *buf, size_t len)
{
    while (len > 0) {
        ssize_t result = read(s, buf, len);
        if ((result < 0) && (errno == EINTR))
            continue;
        if (result <= 0)
            return -1;
        buf = (char*)buf + result;
        len -= result;
    }
    return 0;
}

static int write_all(int s, const void *buf, size_t len)
{
    while (len > 0) {
        ssize_t result = write(s, buf, len);
        if ((result < 0) && (errno == EINTR))
            continue;
        if (result <= 0)
            return -1;
        buf = (const char*)buf + result;
        len -= result;
    }
    return 0;
}

static int count_bits(int value)
{
    int i, count;
    for (i = 0, count = 0; i < 32; i++) {
        if (value & (1 << i))
            count++;
    }
    return count;
}

static int negotiate_pov(int s)
{
    int type, secret, i;
    int data[3];
    uint8_t secret_page[4096];

    shared->pov_valid = 0;

    if (read_all(s, &type, sizeof(type)) != 0) {
        fprintf(stderr, "PoV negotiation failed: did not receive type\n");
        return 0;
    }

    if (type == 1) {
        static const char *reg_names[8] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};

        fprintf(stderr, "PoV negotiating type 1\n");

        if (read_all(s, data, sizeof(int) * 3) != 0) {
            fprintf(stderr, "PoV negotiation failed: did not receive register and masks\n");
            return 0;
        }

        if (count_bits(data[0]) < 20) {
            fprintf(stderr, "PoV negotiation failed: IP mask %.8x did not have at least 20 bits set\n", data[0]);
            return 0;
        }
        if (count_bits(data[1]) < 20) {
            fprintf(stderr, "PoV negotiation failed: register mask %.8x did not have at least 20 bits set\n", data[0]);
            return 0;
        }
        if ((data[2] < 0) || (data[2] >= 8)) {
            fprintf(stderr, "PoV negotiation failed: invalid target register\n");
            return 0;
        }

        fprintf(stderr, "PoV using IP mask %.8x and register %s with mask %.8x\n", data[0], reg_names[data[2]], data[1]);
        shared->pov_ip_mask = data[0];
        shared->pov_reg_mask = data[1];
        shared->pov_reg_index = data[2];

        AES_set_encrypt_key(&negotiate_random_seed[16], 128, &random_key);
        get_random_bytes((uint8_t*)data, sizeof(int) * 2);

        data[0] &= shared->pov_ip_mask;
        data[1] &= shared->pov_reg_mask;
        shared->pov_ip_expected_value = data[0];
        shared->pov_reg_expected_value = data[1];
        shared->pov_type_1_active = 1;

        if (write_all(s, data, sizeof(int) * 2) != 0) {
            fprintf(stderr, "PoV negotiation failed: send error\n");
            return 0;
        }

        return 1;
    } else if (type == 2) {
        fprintf(stderr, "PoV negotiating type 2\n");
        data[0] = CGC_MAGIC_PAGE;
        data[1] = 0x1000;
        data[2] = 4;
        if (write_all(s, data, sizeof(int) * 3) != 0) {
            fprintf(stderr, "PoV negotiation failed: send error\n");
            return 0;
        }

        if (read_all(s, &secret, sizeof(secret)) != 0) {
            fprintf(stderr, "PoV negotiation failed: did not receive secret\n");
        }

        fprintf(stderr, "PoV reports secret value %.8x\n", secret);

        AES_set_encrypt_key(&random_seed[16], 128, &random_key);
        get_random_bytes(secret_page, 4096);

        for (i = 0; i <= (4096 - 4); i++) {
            if (*((int*)(&secret_page[i])) == secret) {
                fprintf(stderr, "PoV type 2 verified\n");
                shared->pov_valid = 1;
                return 1;
            }
        }

        fprintf(stderr, "PoV negotiation failed: secret value not valid\n");
    } else {
        fprintf(stderr, "PoV negotiation failed: invalid PoV type requested\n");
    }

    return 0;
}

int is_pov_process(void)
{
    return is_pov;
}

static void init_shared_region(void)
{
    int i;
    pthread_mutexattr_t attr;
    pthread_condattr_t condattr;

    /* Allocate shared memory for communicating across binaries */
#ifdef MAP_HASSEMAPHORE
    shared = mmap(NULL, sizeof(struct shared_data), PROT_READ | PROT_WRITE,
                  MAP_ANONYMOUS | MAP_HASSEMAPHORE | MAP_SHARED, -1, 0);
#else
    shared = mmap(NULL, sizeof(struct shared_data), PROT_READ | PROT_WRITE,
                  MAP_ANONYMOUS | MAP_SHARED, -1, 0);
#endif
    if (!shared) {
        fprintf(stderr, "Unable to allocate shared memory\n");
        _exit(1);
    }
    memset(shared, 0, sizeof(struct shared_data));

    shared->global_ordering_index = 0;

    /* Initialize mutexes in the shared memory region.  These mutexes will be used to
     * guarantee ordering when reading and writing to sockets. */
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
    pthread_mutex_init(&shared->client_read_mutex, &attr);
    pthread_mutex_init(&shared->client_write_mutex, &attr);
    pthread_mutex_init(&shared->error_read_mutex, &attr);
    pthread_mutex_init(&shared->error_write_mutex, &attr);
    shared->read_mutex[0] = &shared->client_read_mutex;
    shared->write_mutex[0] = &shared->client_write_mutex;
    shared->read_mutex[1] = &shared->client_read_mutex;
    shared->write_mutex[1] = &shared->client_write_mutex;
    shared->read_mutex[2] = &shared->error_read_mutex;
    shared->write_mutex[2] = &shared->error_write_mutex;
    for (i = 0; i < MAX_BINARIES; i++) {
        pthread_mutex_init(&shared->binary_read_mutex[i], &attr);
        pthread_mutex_init(&shared->binary_write_mutex[i], &attr);
        shared->read_mutex[3 + i * 2] = &shared->binary_read_mutex[i];
        shared->write_mutex[3 + i * 2] = &shared->binary_write_mutex[i];
        shared->read_mutex[4 + i * 2] = &shared->binary_read_mutex[i];
        shared->write_mutex[4 + i * 2] = &shared->binary_write_mutex[i];
    }

    /* Initialize synchronization for system call ordering during replay */
    pthread_mutex_init(&shared->syscall_ordering_mutex, &attr);
    pthread_condattr_init(&condattr);
    pthread_condattr_setpshared(&condattr, PTHREAD_PROCESS_SHARED);
    pthread_cond_init(&shared->syscall_ordering_cond, &condattr);
}

int main(int argc, char **argv)
{
    struct target_pt_regs regs1, *regs = &regs1;
    struct image_info info1, *info = &info1;
    struct linux_binprm bprm;
    TaskState *ts;
    CPUArchState *env;
    CPUState *cpu;
    int optind;
    int ret, exit_status;
    int i;
    pid_t* children;
    int* ipc_sockets = NULL;
    int is_parent;
    const char* filename;
    abi_ulong error;

    signal(SIGPIPE, SIG_IGN);

    module_call_init(MODULE_INIT_QOM);

    cpu_model = NULL;
#if defined(cpudef_setup)
    cpudef_setup(); /* parse cpu definitions in target config file (TBD) */
#endif

    init_analysis();

    srand(time(NULL));
    for (i = 0; i < 48; i++)
        random_seed[i] = (uint8_t)rand();
    for (i = 0; i < 48; i++)
        pov_random_seed[i] = (uint8_t)rand();
    for (i = 0; i < 48; i++)
        negotiate_random_seed[i] = (uint8_t)rand();

    optind = parse_args(argc, argv);

    init_shared_region();

    /* For multi-executable challenge binaries, we need to set up the IPC socket pairs.
       Each executable has a socket pair associated with it, starting at descriptor 3. */
    binary_count = argc - optind;
    if (binary_count > 1) {
        ipc_sockets = g_malloc0(sizeof(int) * binary_count * 2);

        for (i = 0; i < binary_count; i++) {
            if (socketpair(AF_UNIX, SOCK_STREAM, 0, &ipc_sockets[i * 2]) < 0) {
                fprintf(stderr, "Unable to create socket pair for IPC\n");
                _exit(1);
            }
        }
    }

    /* If running a PoV, create a socket for communication between the PoV and the CB */
    if (pov_name != NULL) {
        if (pipe(pov_pipes) < 0) {
            fprintf(stderr, "Unable to create pipe for PoV\n");
            _exit(1);
        }
        if (pipe(&pov_pipes[2]) < 0) {
            fprintf(stderr, "Unable to create pipe for PoV\n");
            _exit(1);
        }
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, pov_negotiate_sockets) < 0) {
            fprintf(stderr, "Unable to create socket pair for PoV negotiation\n");
            _exit(1);
        }
    }

    /* If debugging is desired, check for compatibility */
    if (gdbstub_port && (binary_count > 1)) {
        fprintf(stderr, "Debugging of multiple binaries is not supported. You can debug individual\n");
        fprintf(stderr, "processes by recording a replay with the '-record' option, then debugging\n");
        fprintf(stderr, "a replay of an individual process by running only the desired binary with\n");
        fprintf(stderr, "the '-replay' option.\n");
        exit(1);
    }

    /* Zero out regs */
    memset(regs, 0, sizeof(struct target_pt_regs));

    /* Zero out image_info */
    memset(info, 0, sizeof(struct image_info));

    memset(&bprm, 0, sizeof (bprm));

    if (cpu_model == NULL) {
#if defined(TARGET_I386)
        cpu_model = "Haswell";
#else
        cpu_model = "any";
#endif
    }
    tcg_exec_init(0);
    cpu_exec_init_all();
    /* NOTE: we need to init the CPU at this stage to get
       qemu_host_page_size */
    env = cpu_init(cpu_model);
    if (!env) {
        fprintf(stderr, "Unable to find CPU definition\n");
        exit(1);
    }
    cpu = ENV_GET_CPU(env);
    cpu_reset(cpu);

    thread_cpu = cpu;

    if (getenv("QEMU_STRACE")) {
        do_strace = 1;
    }

    if (getenv("QEMU_RAND_SEED")) {
        handle_arg_randseed(getenv("QEMU_RAND_SEED"));
    }

    if (getenv("QEMU_MAX_RECV")) {
        handle_arg_maxrecv(getenv("QEMU_MAX_RECV"));
    }

#if defined(CONFIG_USE_GUEST_BASE)
    /*
     * Now that page sizes are configured in cpu_init() we can do
     * proper page alignment for guest_base.
     */
    guest_base = HOST_PAGE_ALIGN(guest_base);

    if (reserved_va || have_guest_base) {
        guest_base = init_guest_space(guest_base, reserved_va, 0,
                                      have_guest_base);
        if (guest_base == (unsigned long)-1) {
            fprintf(stderr, "Unable to reserve 0x%lx bytes of virtual address "
                    "space for use as guest address space (check your virtual "
                    "memory ulimit setting or reserve less using -R option)\n",
                    reserved_va);
            exit(1);
        }

        if (reserved_va) {
            if (reserved_va >= DECREE_MAX_ALLOC_ADDRESS) {
                /*
                 * Match the decree starting dynamic allocation address if the guest
                 * space is big enough.
                 */
                mmap_next_start = DECREE_MAX_ALLOC_ADDRESS;
            } else {
                mmap_next_start = reserved_va;
            }
        }
    }
#else
    fprintf(stderr, "Guest base is disabled, memory layout will not be accurate\n");
#endif /* CONFIG_USE_GUEST_BASE */

    ts = g_malloc0 (sizeof(TaskState));
    init_task_state(ts);
    /* build Task State */
    ts->info = info;
    ts->bprm = &bprm;
    cpu->opaque = ts;
    task_settid(ts);

    /* Challenge binaries can be composed of one or more executables, if it is a single
       executable, start running it immediately as there is no setup necessary */
    binary_count = argc - optind;
    if (binary_count > MAX_BINARIES) {
        fprintf(stderr, "Maximum binary count (%d) exceeded.\n", MAX_BINARIES);
        _exit(1);
    }

    if ((replay_playback_count > 0) && (binary_count > 1) && (replay_playback_count != binary_count)) {
        fprintf(stderr, "Expected one replay file for each binary.\n");
        _exit(1);
    }
    if ((replay_playback_count > 1) && (binary_count == 1)) {
        fprintf(stderr, "Too many replay files given.\n");
        _exit(1);
    }

    /* Grab starting reference time before starting binaries, this must be shared among
       all running binaries to have a common reference point. */
    shared->base_wall_time = get_physical_wall_time();

    if ((binary_count == 1) && (pov_name == NULL)) {
        binary_index = 0;
        filename = argv[optind];
        open_and_load_file(filename, regs, info, &bprm);
    } else {
        signal(SIGCHLD, sigchild_handler);

        /* Multi-executable binaries need to create child processes for each executable */
        children = g_malloc0(sizeof(pid_t) * binary_count);
        is_parent = 1;
        for (i = 0; i < binary_count; i++) {
            /* Create a child process and execute the binary */
            children[i] = fork();
            if (children[i] == 0) {
                is_parent = 0;
                binary_index = i;
                filename = argv[optind + i];
                open_and_load_file(filename, regs, info, &bprm);
                break;
            }
        }

        if (is_parent && (pov_name != NULL)) {
            pov_pid = fork();
            if (pov_pid == 0) {
                is_parent = 0;
                binary_index = 0;
                binary_count = 1;
                is_pov = 1;
                record_replay_flags |= REPLAY_FLAG_POV;
                filename = pov_name;
                open_and_load_file(filename, regs, info, &bprm);

                /* Reinitialize the shared region so that CB replays are not impacted by the PoV replay */
                init_shared_region();
            }
        }

        if (is_parent) {
            /* Close IPC sockets on parent so that children can terminate cleanly */
            if (binary_count > 1) {
                for (i = 0; i < binary_count; i++) {
                    close(ipc_sockets[2 * i]);
                    close(ipc_sockets[1 + 2 * i]);
                }
            }
            if (pov_name != NULL) {
                for (i = 0; i < 4; i++) {
                    close(pov_pipes[i]);
                }
                close(pov_negotiate_sockets[0]);
            }

            /* If a PoV is running, process negotiation in the parent process */
            if (pov_name != NULL) {
                negotiate_pov(pov_negotiate_sockets[1]);
                close(pov_negotiate_sockets[1]);
            }

            /* Parent should wait for all children to exit and return a combined status code */
            exit_status = 0;

            for (i = 0; i < binary_count; i++) {
                waitpid(children[i], &ret, 0);

                if (!exit_status && WIFEXITED(ret))
                    exit_status = WEXITSTATUS(ret);
                if ((exit_status >= 0) && WIFSIGNALED(ret) && WTERMSIG(ret) != SIGUSR1)
                    exit_status = -WTERMSIG(ret);
            }

            if (pov_name != NULL) {
                waitpid(pov_pid, &ret, 0);

                if (!exit_status && WIFEXITED(ret))
                    exit_status = WEXITSTATUS(ret);
                if ((exit_status >= 0) && WIFSIGNALED(ret) && WTERMSIG(ret) != SIGUSR1)
                    exit_status = -WTERMSIG(ret);
            }

            if (exit_status < 0) {
                /* One or more children crashed, report this to the caller */
                struct rlimit rlim = {0, 0};
                setrlimit(RLIMIT_CORE, &rlim);
                raise(-exit_status);
                pause();
            }

            _exit(exit_status);
        } else if (is_pov) {
            /* PoV process, stdin/stdout are connected to running CB */
            close(0);
            close(1);
            dup2(pov_pipes[2], 0);
            dup2(pov_pipes[1], 1);

            for (i = 0; i < 4; i++) {
                close(pov_pipes[i]);
            }

            dup2(pov_negotiate_sockets[0], 3);
            close(pov_negotiate_sockets[0]);
            close(pov_negotiate_sockets[1]);
        } else {
            /* Child process, move IPC socket pairs into the correct file descriptor */
            if (binary_count > 1) {
                for (i = 0; i < binary_count; i++) {
                    if (dup2(ipc_sockets[i * 2], 3 + i * 2) < 0) {
                        fprintf(stderr, "Unable to redirect socket pair to IPC file descriptor\n");
                        _exit(1);
                    }
                    if (ipc_sockets[i * 2] != (3 + i * 2))
                        close(ipc_sockets[i * 2]);

                    if (dup2(ipc_sockets[1 + i * 2], 4 + i * 2) < 0) {
                        fprintf(stderr, "Unable to redirect socket pair to IPC file descriptor\n");
                        _exit(1);
                    }
                    if (ipc_sockets[1 + i * 2] != (4 + i * 2))
                        close(ipc_sockets[1 + i * 2]);
                }
            }

            if (pov_name != NULL) {
                /* PoV process running, connect CB stdin/stdout to the PoV process */
                close(0);
                close(1);
                dup2(pov_pipes[0], 0);
                dup2(pov_pipes[3], 1);
                for (i = 0; i < 4; i++) {
                    close(pov_pipes[i]);
                }
                close(pov_negotiate_sockets[0]);
                close(pov_negotiate_sockets[1]);
            }
        }
    }

    if (record_replay_name) {
        /* If recording a replay, open the replay file now */
        char* replay_filename;
        char* binary_path = strdup(filename);
        char* binary_basename = basename(binary_path);

        if (is_pov) {
            if (asprintf(&replay_filename, "%s.pov.replay", record_replay_name) < 0) {
                fprintf(stderr, "Invalid replay file name\n");
                _exit(1);
            }
        } else {
            if (asprintf(&replay_filename, "%s-%s.replay", record_replay_name, binary_basename) < 0) {
                fprintf(stderr, "Invalid replay file name\n");
                _exit(1);
            }
        }

        free(binary_path);

        if (!replay_create(replay_filename, record_replay_flags, random_seed)) {
            fprintf(stderr, "Replay file not created\n");
            _exit(1);
        }

        free(replay_filename);
    } else if (replay_playback_count > 0) {
        /* If playing back a replay, open the replay file */
        if (!replay_open(replay_playback_name[binary_index])) {
            fprintf(stderr, "Replay file invalid for binary '%s'\n", argv[optind + binary_index]);
            _exit(1);
        }

        /* Set options from header flags */
        limit_closed_fd_ops = ((get_replay_flags() & REPLAY_FLAG_LIMIT_CLOSED_FD_LOOP) != 0);
        is_pov = ((get_replay_flags() & REPLAY_FLAG_POV) != 0);
    }

    if (analysis_output_name) {
        /* If generating analysis output, open the file now */
        char* output_filename;
        char* binary_path = strdup(filename);
        char* binary_basename = basename(binary_path);

        if (asprintf(&output_filename, "%s-%s.analyze", analysis_output_name, binary_basename) < 0) {
            fprintf(stderr, "Invalid analysis output file name\n");
            _exit(1);
        }

        free(binary_path);

        if (!analysis_output_create(output_filename)) {
            fprintf(stderr, "Analysis output file not created\n");
            _exit(1);
        }

        free(output_filename);

        activate_pending_analysis(env);
    }

    /* Initialize random generator */
    AES_set_encrypt_key(&random_seed[16], 128, &random_key);

    /* Create and populate CGC magic page */
    error = target_mmap(CGC_MAGIC_PAGE, 4096, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (error == -1) {
        perror("mmap magic page");
        exit(-1);
    }

    get_random_bytes((uint8_t *) g2h(error), 4096);
    target_mprotect(error, 4096, PROT_READ);

    /* Initialize file descriptor validitity */
    memset(fd_valid, 0, sizeof(fd_valid));
    for (i = 0; i < (3 + binary_count * 2); i++)
        fd_valid[i] = 1;

    /* If a timeout has been set, activate it now */
    if (timeout > 0) {
        alarm(timeout);
    }

    if (qemu_log_enabled()) {
#if defined(CONFIG_USE_GUEST_BASE)
        qemu_log("guest_base  0x%lx\n", guest_base);
#endif
        log_page_dump();

        qemu_log("start_brk   0x" TARGET_ABI_FMT_lx "\n", info->start_brk);
        qemu_log("end_code    0x" TARGET_ABI_FMT_lx "\n", info->end_code);
        qemu_log("start_code  0x" TARGET_ABI_FMT_lx "\n",
                 info->start_code);
        qemu_log("start_data  0x" TARGET_ABI_FMT_lx "\n",
                 info->start_data);
        qemu_log("end_data    0x" TARGET_ABI_FMT_lx "\n", info->end_data);
        qemu_log("start_stack 0x" TARGET_ABI_FMT_lx "\n",
                 info->start_stack);
        qemu_log("brk         0x" TARGET_ABI_FMT_lx "\n", info->brk);
        qemu_log("entry       0x" TARGET_ABI_FMT_lx "\n", info->entry);
    }

    /* target_set_brk(info->brk); */
    syscall_init();
    signal_init();

#if defined(CONFIG_USE_GUEST_BASE)
    /* Now that we've loaded the binary, GUEST_BASE is fixed.  Delay
       generating the prologue until now so that the prologue can take
       the real value of GUEST_BASE into account.  */
    tcg_prologue_init(&tcg_ctx);
#endif

#if defined(TARGET_I386)
    env->cr[0] = CR0_PG_MASK | CR0_WP_MASK | CR0_PE_MASK;
    env->hflags |= HF_PE_MASK | HF_CPL_MASK;
    if (env->features[FEAT_1_EDX] & CPUID_SSE) {
        env->cr[4] |= CR4_OSFXSR_MASK;
        env->hflags |= HF_OSFXSR_MASK;
    }

    /* flags setup : we activate the IRQs by default as in user mode */
    env->eflags |= IF_MASK;

    /* linux register setup */
    env->regs[R_EAX] = regs->eax;
    env->regs[R_EBX] = regs->ebx;
    env->regs[R_ECX] = regs->ecx;
    env->regs[R_EDX] = regs->edx;
    env->regs[R_ESI] = regs->esi;
    env->regs[R_EDI] = regs->edi;
    env->regs[R_EBP] = regs->ebp;
    env->regs[R_ESP] = regs->esp;
    env->eip = regs->eip;

    /* Set up IDT and GDT addresses to look like a Linux system, these will not actually be
     * used during execution. */
    env->idt.limit = 0x7ff;
    env->idt.base = 0xffffb000;
    env->gdt.limit = 0xff;
    env->gdt.base = 0xc1436000;

    /* linux segment setup */
    cpu_x86_load_seg(env, R_CS, __USER_CS);
    cpu_x86_load_seg(env, R_SS, __USER_DS);
    cpu_x86_load_seg(env, R_DS, __USER_DS);
    cpu_x86_load_seg(env, R_ES, __USER_DS);
    cpu_x86_load_seg(env, R_FS, __USER_DS);
    cpu_x86_load_seg(env, R_GS, __USER_DS);
#else
#error unsupported target CPU
#endif

    if (is_replaying()) {
        /* Replay should have a start event at the beginning */
        struct replay_event evt;
        void* data;

        data = read_replay_event(env, &evt);
        if ((evt.event_id != REPLAY_EVENT_START)) {
            fprintf(stderr, "Replay event mismatch at index %d\n", evt.global_ordering);
            abort();
        }

        free_replay_event(data);
    } else {
        /* Generate a startup event so that initial instruction timing is more accurate */
        replay_write_event(env, REPLAY_EVENT_START, 0, 0);
    }

    if (gdbstub_port) {
        if (gdbserver_start(gdbstub_port) < 0) {
            fprintf(stderr, "qemu: could not open gdbserver on port %d\n",
                    gdbstub_port);
            exit(1);
        }
        gdb_handlesig(cpu, 0);
    }
    cpu_loop(env);
    /* never exits */
    return 0;
}
