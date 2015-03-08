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
int timeout = 0;
int random_seed;

static char* record_replay_name = NULL;
static char* replay_playback_name = NULL;
int record_replay_flags = 0;

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

void cpu_loop(CPUX86State *env)
{
    CPUState *cs = CPU(x86_env_get_cpu(env));
    int trapnr;
    abi_ulong pc, orig_eax;
    target_siginfo_t info;

    for(;;) {
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
    replay_playback_name = strdup(arg);
}

static void handle_arg_compact(const char* arg)
{
    record_replay_flags |= REPLAY_FLAG_COMPACT;
}

static void handle_arg_randseed(const char *arg)
{
    unsigned long long seed;

    if (parse_uint_full(arg, &seed, 0) != 0 || seed > UINT_MAX) {
        fprintf(stderr, "Invalid seed number: %s\n", arg);
        exit(1);
    }
    random_seed = seed;
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
    {"singlestep", "QEMU_SINGLESTEP",  false, handle_arg_singlestep,
     "",           "run in singlestep mode"},
    {"strace",     "QEMU_STRACE",      false, handle_arg_strace,
     "",           "log system calls"},
    {"seed",       "QEMU_RAND_SEED",   true,  handle_arg_randseed,
     "",           "Seed for pseudo-random number generator"},
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
    if (binary_count <= 1) /* If single binary, only stdin/stdout/stderr are valid */
        return 0;
    if (fd <= (4 + 2 * binary_count)) /* For multi-binary, allow socket pairs */
        return 1;
    return 0;
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

    signal(SIGPIPE, SIG_IGN);

    module_call_init(MODULE_INIT_QOM);

    cpu_model = NULL;
#if defined(cpudef_setup)
    cpudef_setup(); /* parse cpu definitions in target config file (TBD) */
#endif

    random_seed = (int)time(NULL);

    optind = parse_args(argc, argv);

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
    if (binary_count == 1) {
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
                filename = argv[optind + i];
                open_and_load_file(filename, regs, info, &bprm);
                break;
            }
        }

        if (is_parent) {
            /* Close IPC sockets on parent so that children can terminate cleanly */
            for (i = 0; i < binary_count; i++) {
                close(3 + 2 * i);
                close(4 + 2 * i);
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

            if (exit_status < 0) {
                /* One or more children crashed, report this to the caller */
                struct rlimit rlim = {0, 0};
                setrlimit(RLIMIT_CORE, &rlim);
                raise(-exit_status);
                pause();
            }

            _exit(exit_status);
        } else {
            /* Child process, move IPC socket pairs into the correct file descriptor */
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
    }

    if (record_replay_name) {
        /* If recording a replay, open the replay file now */
        char* replay_filename;
        char* binary_path = strdup(filename);
        char* binary_basename = basename(binary_path);

        asprintf(&replay_filename, "%s-%s.replay", record_replay_name, binary_basename);
        free(binary_path);

        if (!replay_create(replay_filename, record_replay_flags, random_seed)) {
            fprintf(stderr, "Replay file not created\n");
            _exit(1);
        }

        free(replay_filename);
    } else if (replay_playback_name) {
        /* If playing back a replay, open the replay file */
        if (!replay_open(replay_playback_name)) {
            fprintf(stderr, "Replay file invalid\n");
            _exit(1);
        }
    }

    /* Now that the optional replay file is ready and we are about to execute, set the random seed */
    srand(random_seed);

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
