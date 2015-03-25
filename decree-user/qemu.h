#ifndef QEMU_H
#define QEMU_H

#include <signal.h>
#include <string.h>

#include "cpu.h"
#include "exec/cpu_ldst.h"

#undef DEBUG_REMAP
#ifdef DEBUG_REMAP
#include <stdlib.h>
#endif /* DEBUG_REMAP */

#include "exec/user/abitypes.h"

#include "exec/user/thunk.h"
#include "syscall_defs.h"
#include "syscall.h"
#include "exec/gdbstub.h"
#include "qemu/queue.h"

#define THREAD __thread

/* This struct is used to hold certain information about the image.
 * Basically, it replicates in user space what would be certain
 * task_struct fields in the kernel
 */
struct image_info {
        abi_ulong       load_bias;
        abi_ulong       load_addr;
        abi_ulong       start_code;
        abi_ulong       end_code;
        abi_ulong       start_data;
        abi_ulong       end_data;
        abi_ulong       start_brk;
        abi_ulong       brk;
        abi_ulong       start_mmap;
        abi_ulong       mmap;
        abi_ulong       rss;
        abi_ulong       start_stack;
        abi_ulong       stack_limit;
        abi_ulong       entry;
        abi_ulong       code_offset;
        abi_ulong       data_offset;
        abi_ulong       saved_auxv;
        abi_ulong       auxv_len;
        abi_ulong       arg_start;
        abi_ulong       arg_end;
        uint32_t        elf_flags;
	int		personality;
#ifdef CONFIG_USE_FDPIC
        abi_ulong       loadmap_addr;
        uint16_t        nsegs;
        void           *loadsegs;
        abi_ulong       pt_dynamic_addr;
        struct image_info *other_info;
#endif
};

#ifdef TARGET_I386
/* Information about the current linux thread */
struct vm86_saved_state {
    uint32_t eax; /* return code */
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
    uint32_t esi;
    uint32_t edi;
    uint32_t ebp;
    uint32_t esp;
    uint32_t eflags;
    uint32_t eip;
    uint16_t cs, ss, ds, es, fs, gs;
};
#endif

#define MAX_SIGQUEUE_SIZE 1024

struct sigqueue {
    struct sigqueue *next;
    target_siginfo_t info;
};

struct emulated_sigtable {
    int pending; /* true if signal is pending */
    struct sigqueue *first;
    struct sigqueue info; /* in order to always have memory for the
                             first signal, we put it here */
};

/* NOTE: we force a big alignment so that the stack stored after is
   aligned too */
typedef struct TaskState {
    pid_t ts_tid;     /* tid (or pid) of this task */
#if defined(TARGET_I386) && !defined(TARGET_X86_64)
    abi_ulong target_v86;
    struct vm86_saved_state vm86_saved_regs;
    struct target_vm86plus_struct vm86plus;
    uint32_t v86flags;
    uint32_t v86mask;
#endif
    abi_ulong child_tidptr;
    uint32_t stack_base;
    int used; /* non zero if used */
    bool sigsegv_blocked; /* SIGSEGV blocked by guest */
    struct image_info *info;
    struct linux_binprm *bprm;

    struct emulated_sigtable sigtab[TARGET_NSIG];
    struct sigqueue sigqueue_table[MAX_SIGQUEUE_SIZE]; /* siginfo queue */
    struct sigqueue *first_free; /* first free siginfo queue entry */
    int signal_pending; /* non zero if a signal may be pending */
} __attribute__((aligned(16))) TaskState;

void init_task_state(TaskState *ts);
void task_settid(TaskState *);
void stop_all_tasks(void);
extern unsigned long mmap_min_addr;
extern int binary_count;
extern int binary_index;
extern int random_seed;
extern long max_recv;

#define MAX_BINARIES 64
#define MAX_FD (5 + MAX_BINARIES * 2)

struct shared_data {
    /* The starting clock for all binaries should be the same */
    uint32_t base_wall_time;

    /* Keep a global index for determining the order of syscalls across all processes */
    volatile uint32_t global_ordering_index;

    /* Keep a per-socket mutex to ensure that writes to individual sockets are guaranteed
     * to be in an order that is tracked by the global_ordering_index */
    pthread_mutex_t *read_mutex[MAX_FD];
    pthread_mutex_t *write_mutex[MAX_FD];
    pthread_mutex_t client_read_mutex;
    pthread_mutex_t client_write_mutex;
    pthread_mutex_t error_read_mutex;
    pthread_mutex_t error_write_mutex;
    pthread_mutex_t binary_read_mutex[MAX_BINARIES];
    pthread_mutex_t binary_write_mutex[MAX_BINARIES];

    /* This mutex will be held during replay by only one process at a time, which is the next
       process to receive a syscall according to the global ordering index stored in the
       replay files.  This will guarantee that the ordering of syscalls in the replay is
       same as it was during the first execution, so that analysis such as taint tracking
       can work across binary boundaries. */
    pthread_mutex_t syscall_ordering_mutex;
    pthread_cond_t syscall_ordering_cond;
};

extern struct shared_data *shared;

/* Read a good amount of data initially, to hopefully get all the
   program headers loaded.  */
#define BPRM_BUF_SIZE  1024

/*
 * This structure is used to hold the arguments that are
 * used when loading binaries.
 */
struct linux_binprm {
    char buf[BPRM_BUF_SIZE] __attribute__((aligned));
    abi_ulong p;
	int fd;
    int e_uid, e_gid;
    char * filename;        /* Name of binary */
    int (*core_dump)(int, const CPUArchState *); /* coredump routine */
};

void do_init_thread(struct target_pt_regs *regs, struct image_info *infop);
abi_ulong loader_build_argptr(int envc, int argc, abi_ulong sp,
                              abi_ulong stringp, int push_ptr);
int loader_exec(int fdexec, const char *filename,
             struct target_pt_regs * regs, struct image_info *infop,
             struct linux_binprm *);

int load_cgc_binary(struct linux_binprm *bprm, struct image_info *info);

abi_long memcpy_to_target(abi_ulong dest, const void *src,
                          unsigned long len);
void target_set_brk(abi_ulong new_brk);
abi_long do_brk(abi_ulong new_brk);
void syscall_init(void);
abi_long do_syscall(CPUArchState *env, int num, abi_long arg1,
                    abi_long arg2, abi_long arg3, abi_long arg4,
                    abi_long arg5, abi_long arg6);
void gemu_log(const char *fmt, ...) GCC_FMT_ATTR(1, 2);
extern THREAD CPUState *thread_cpu;
void cpu_loop(CPUArchState *env);
char *target_strerror(int err);
int get_osversion(void);
void init_qemu_uname_release(void);

/* Creates the initial guest address space in the host memory space using
 * the given host start address hint and size.  The guest_start parameter
 * specifies the start address of the guest space.  guest_base will be the
 * difference between the host start address computed by this function and
 * guest_start.  If fixed is specified, then the mapped address space must
 * start at host_start.  The real start address of the mapped memory space is
 * returned or -1 if there was an error.
 */
unsigned long init_guest_space(unsigned long host_start,
                               unsigned long host_size,
                               unsigned long guest_start,
                               bool fixed);

#include "qemu/log.h"

/* syscall.c */
int host_to_target_waitstatus(int status);

/* strace.c */
void print_syscall(int num,
                   abi_long arg1, abi_long arg2, abi_long arg3,
                   abi_long arg4, abi_long arg5, abi_long arg6);
void print_syscall_ret(int num, abi_long ret,
                       abi_long arg1, abi_long arg2, abi_long arg3,
                       abi_long arg4, abi_long arg5, abi_long arg6);
extern int do_strace;

/* signal.c */
void process_pending_signals(CPUArchState *cpu_env);
void signal_init(void);
int queue_signal(CPUArchState *env, int sig, target_siginfo_t *info);
void host_to_target_siginfo(target_siginfo_t *tinfo, const siginfo_t *info);
void target_to_host_siginfo(siginfo_t *info, const target_siginfo_t *tinfo);
int target_to_host_signal(int sig);
int host_to_target_signal(int sig);
long do_sigreturn(CPUArchState *env);
long do_rt_sigreturn(CPUArchState *env);
abi_long do_sigaltstack(abi_ulong uss_addr, abi_ulong uoss_addr, abi_ulong sp);
int do_sigprocmask(int how, const sigset_t *set, sigset_t *oldset);

/* mmap.c */
int target_mprotect(abi_ulong start, abi_ulong len, int prot);
abi_long target_mmap(abi_ulong start, abi_ulong len, int prot,
                     int flags, int fd, abi_ulong offset);
int target_munmap(abi_ulong start, abi_ulong len);
extern unsigned long last_brk;
extern abi_ulong mmap_next_start;
void mmap_lock(void);
void mmap_unlock(void);
abi_ulong mmap_find_vma(abi_ulong, abi_ulong);
void cpu_list_lock(void);
void cpu_list_unlock(void);

int is_valid_guest_fd(int fd);

/* user access */

#define VERIFY_READ 0
#define VERIFY_WRITE 1 /* implies read access */

static inline int access_ok(int type, abi_ulong addr, abi_ulong size)
{
    return page_check_range((target_ulong)addr, size,
                            (type == VERIFY_READ) ? PAGE_READ : (PAGE_READ | PAGE_WRITE)) == 0;
}

/* NOTE __get_user and __put_user use host pointers and don't check access.
   These are usually used to access struct data members once the struct has
   been locked - usually with lock_user_struct.  */

/* Tricky points:
   - Use __builtin_choose_expr to avoid type promotion from ?:,
   - Invalid sizes result in a compile time error stemming from
     the fact that abort has no parameters.
   - It's easier to use the endian-specific unaligned load/store
     functions than host-endian unaligned load/store plus tswapN.  */

#define __put_user_e(x, hptr, e)                                        \
  (__builtin_choose_expr(sizeof(*(hptr)) == 1, stb_p,                   \
   __builtin_choose_expr(sizeof(*(hptr)) == 2, stw_##e##_p,             \
   __builtin_choose_expr(sizeof(*(hptr)) == 4, stl_##e##_p,             \
   __builtin_choose_expr(sizeof(*(hptr)) == 8, stq_##e##_p, abort))))   \
     ((hptr), (x)), (void)0)

#define __get_user_e(x, hptr, e)                                        \
  ((x) = (typeof(*hptr))(                                               \
   __builtin_choose_expr(sizeof(*(hptr)) == 1, ldub_p,                  \
   __builtin_choose_expr(sizeof(*(hptr)) == 2, lduw_##e##_p,            \
   __builtin_choose_expr(sizeof(*(hptr)) == 4, ldl_##e##_p,             \
   __builtin_choose_expr(sizeof(*(hptr)) == 8, ldq_##e##_p, abort))))   \
     (hptr)), (void)0)

#ifdef TARGET_WORDS_BIGENDIAN
# define __put_user(x, hptr)  __put_user_e(x, hptr, be)
# define __get_user(x, hptr)  __get_user_e(x, hptr, be)
#else
# define __put_user(x, hptr)  __put_user_e(x, hptr, le)
# define __get_user(x, hptr)  __get_user_e(x, hptr, le)
#endif

/* put_user()/get_user() take a guest address and check access */
/* These are usually used to access an atomic data type, such as an int,
 * that has been passed by address.  These internally perform locking
 * and unlocking on the data type.
 */
#define put_user(x, gaddr, target_type)					\
({									\
    abi_ulong __gaddr = (gaddr);					\
    target_type *__hptr;						\
    abi_long __ret = 0;							\
    if ((__hptr = lock_user(VERIFY_WRITE, __gaddr, sizeof(target_type), 0))) { \
        __put_user((x), __hptr);				\
        unlock_user(__hptr, __gaddr, sizeof(target_type));		\
    } else								\
        __ret = -TARGET_EFAULT;						\
    __ret;								\
})

#define get_user(x, gaddr, target_type)					\
({									\
    abi_ulong __gaddr = (gaddr);					\
    target_type *__hptr;						\
    abi_long __ret = 0;							\
    if ((__hptr = lock_user(VERIFY_READ, __gaddr, sizeof(target_type), 1))) { \
        __get_user((x), __hptr);				\
        unlock_user(__hptr, __gaddr, 0);				\
    } else {								\
        /* avoid warning */						\
        (x) = 0;							\
        __ret = -TARGET_EFAULT;						\
    }									\
    __ret;								\
})

#define put_user_ual(x, gaddr) put_user((x), (gaddr), abi_ulong)
#define put_user_sal(x, gaddr) put_user((x), (gaddr), abi_long)
#define put_user_u64(x, gaddr) put_user((x), (gaddr), uint64_t)
#define put_user_s64(x, gaddr) put_user((x), (gaddr), int64_t)
#define put_user_u32(x, gaddr) put_user((x), (gaddr), uint32_t)
#define put_user_s32(x, gaddr) put_user((x), (gaddr), int32_t)
#define put_user_u16(x, gaddr) put_user((x), (gaddr), uint16_t)
#define put_user_s16(x, gaddr) put_user((x), (gaddr), int16_t)
#define put_user_u8(x, gaddr)  put_user((x), (gaddr), uint8_t)
#define put_user_s8(x, gaddr)  put_user((x), (gaddr), int8_t)

#define get_user_ual(x, gaddr) get_user((x), (gaddr), abi_ulong)
#define get_user_sal(x, gaddr) get_user((x), (gaddr), abi_long)
#define get_user_u64(x, gaddr) get_user((x), (gaddr), uint64_t)
#define get_user_s64(x, gaddr) get_user((x), (gaddr), int64_t)
#define get_user_u32(x, gaddr) get_user((x), (gaddr), uint32_t)
#define get_user_s32(x, gaddr) get_user((x), (gaddr), int32_t)
#define get_user_u16(x, gaddr) get_user((x), (gaddr), uint16_t)
#define get_user_s16(x, gaddr) get_user((x), (gaddr), int16_t)
#define get_user_u8(x, gaddr)  get_user((x), (gaddr), uint8_t)
#define get_user_s8(x, gaddr)  get_user((x), (gaddr), int8_t)

/* copy_from_user() and copy_to_user() are usually used to copy data
 * buffers between the target and host.  These internally perform
 * locking/unlocking of the memory.
 */
abi_long copy_from_user(void *hptr, abi_ulong gaddr, size_t len);
abi_long copy_to_user(abi_ulong gaddr, void *hptr, size_t len);

/* Functions for accessing guest memory.  The tget and tput functions
   read/write single values, byteswapping as necessary.  The lock_user function
   gets a pointer to a contiguous area of guest memory, but does not perform
   any byteswapping.  lock_user may return either a pointer to the guest
   memory, or a temporary buffer.  */

/* Lock an area of guest memory into the host.  If copy is true then the
   host area will have the same contents as the guest.  */
static inline void *lock_user(int type, abi_ulong guest_addr, long len, int copy)
{
    if (!access_ok(type, guest_addr, len))
        return NULL;
#ifdef DEBUG_REMAP
    {
        void *addr;
        addr = malloc(len);
        if (copy)
            memcpy(addr, g2h(guest_addr), len);
        else
            memset(addr, 0, len);
        return addr;
    }
#else
    return g2h(guest_addr);
#endif
}

/* Unlock an area of guest memory.  The first LEN bytes must be
   flushed back to guest memory. host_ptr = NULL is explicitly
   allowed and does nothing. */
static inline void unlock_user(void *host_ptr, abi_ulong guest_addr,
                               long len)
{

#ifdef DEBUG_REMAP
    if (!host_ptr)
        return;
    if (host_ptr == g2h(guest_addr))
        return;
    if (len > 0)
        memcpy(g2h(guest_addr), host_ptr, len);
    free(host_ptr);
#endif
}

/* Return the length of a string in target memory or -TARGET_EFAULT if
   access error. */
abi_long target_strlen(abi_ulong gaddr);

/* Like lock_user but for null terminated strings.  */
static inline void *lock_user_string(abi_ulong guest_addr)
{
    abi_long len;
    len = target_strlen(guest_addr);
    if (len < 0)
        return NULL;
    return lock_user(VERIFY_READ, guest_addr, (long)(len + 1), 1);
}

/* Helper macros for locking/unlocking a target struct.  */
#define lock_user_struct(type, host_ptr, guest_addr, copy)	\
    (host_ptr = lock_user(type, guest_addr, sizeof(*host_ptr), copy))
#define unlock_user_struct(host_ptr, guest_addr, copy)		\
    unlock_user(host_ptr, guest_addr, (copy) ? sizeof(*host_ptr) : 0)

/* Record/replay functions */
#define REPLAY_MAGIC 0xbd46f4dd
#define REPLAY_VERSION 3

#define REPLAY_FLAG_COMPACT 1 /* When set, doesn't include validation information */

struct replay_header {
    uint32_t magic; /* Must equal REPLAY_MAGIC */
    uint16_t version; /* Replay version, set to REPLAY_VERSION */
    uint16_t binary_count; /* Number of binaries running in this challenge */
    uint32_t seed; /* Random seed for this process */
    uint32_t flags; /* See above for available flags */
};

#define REPLAY_EVENT_START 0
#define REPLAY_EVENT_TERMINATE 1
#define REPLAY_EVENT_TRANSMIT 2
#define REPLAY_EVENT_RECEIVE 3
#define REPLAY_EVENT_FDWAIT 4
#define REPLAY_EVENT_RANDOM 7

struct replay_event {
    uint16_t event_id; /* One of REPLAY_EVENT_* */
    uint16_t fd; /* File descriptor for syscalls that take one */
    uint32_t global_ordering; /* Monotonically increasing event number across all running binaries, used for synchronization */
    uint32_t result; /* Result of operation, defined by type of event */
    uint32_t data_length; /* Length of associated data */
    uint32_t start_wall_time; /* Microseconds since start of execution at start of event */
    uint32_t end_wall_time; /* Microseconds since start of execution at end of event */
};

int replay_create(const char* filename, uint32_t flags, uint32_t seed);
int replay_open(const char* filename);
int replay_close(int signal);

uint32_t get_physical_wall_time(void);
uint32_t get_current_wall_time(void);

void replay_begin_event(void);
void replay_nonblocking_event(void);
void replay_write_event(uint16_t id, uint16_t fd, uint32_t result);
void replay_write_event_with_required_data(uint16_t id, uint16_t fd, uint32_t result, const void *data, size_t len);
void replay_write_event_with_validation_data(uint16_t id, uint16_t fd, uint32_t result, const void *data, size_t len);
void replay_write_validation_event(uint16_t id, uint16_t fd, uint32_t result, const void *data, size_t len);

int is_replaying(void);
int replay_has_validation(void);
void* read_replay_event(struct replay_event* evt);
void free_replay_event(void* data);

/* Instrumentation API */
struct Instruction;
typedef int (*InsnInstrumentationFilterFn)(CPUArchState *env, void *data, abi_ulong pc, struct Instruction *insn);
typedef void (*InsnInstrumentationFn)(CPUArchState *env, void* data, struct Instruction *insn);

typedef struct InsnInstrumentation {
    void *data; /* Opaque data for use by the instrumentation implementation */
    InsnInstrumentationFilterFn filter; /* Function that determines if instrumentation is active for a given instruction */
    InsnInstrumentationFn before; /* Function called before instruction is executed */
    InsnInstrumentationFn after; /* Function called after instruction is executed */
    int active; /* Active for this instruction */
    QTAILQ_ENTRY(InsnInstrumentation) entry;
} InsnInstrumentation;

struct InstrumentationState {
    QTAILQ_HEAD(insn_instrumentation_head, InsnInstrumentation) insn_instrumentation;
};

extern struct InstrumentationState instrumentation;

InsnInstrumentation *add_insn_instrumentation(CPUArchState *env, InsnInstrumentationFilterFn filter,
                                              InsnInstrumentationFn before, InsnInstrumentationFn after,
                                              void *data);
void remove_insn_instrumentation(CPUArchState *env, InsnInstrumentation *instrument);

#include <pthread.h>

/* Include target-specific struct and function definitions;
 * they may need access to the target-independent structures
 * above, so include them last.
 */
#include "target_cpu.h"
#include "target_signal.h"
#include "target_structs.h"

#endif /* QEMU_H */
