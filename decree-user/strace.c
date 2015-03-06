#include <stdio.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sched.h>
#include "qemu.h"

int do_strace=0;

struct syscallname {
    int nr;
    const char *name;
    const char *format;
    void (*call)(const struct syscallname *,
                 abi_long, abi_long, abi_long,
                 abi_long, abi_long, abi_long);
    void (*result)(const struct syscallname *, abi_long);
};

#ifdef __GNUC__
/*
 * It is possible that target doesn't have syscall that uses
 * following flags but we don't want the compiler to warn
 * us about them being unused.  Same applies to utility print
 * functions.  It is ok to keep them while not used.
 */
#define UNUSED __attribute__ ((unused))
#else
#define UNUSED
#endif

/*
 * Structure used to translate flag values into strings.  This is
 * similar that is in the actual strace tool.
 */
struct flags {
    abi_long    f_value;  /* flag */
    const char  *f_string; /* stringified flag */
};

/* common flags for all architectures */
#define FLAG_GENERIC(name) { name, #name }
/* target specific flags (syscall_defs.h has TARGET_<flag>) */
#define FLAG_TARGET(name)  { TARGET_ ## name, #name }
/* end of flags array */
#define FLAG_END           { 0, NULL }

UNUSED static const char *get_comma(int);
UNUSED static void print_pointer(abi_long, int);
UNUSED static void print_flags(const struct flags *, abi_long, int);
UNUSED static void print_syscall_prologue(const struct syscallname *);
UNUSED static void print_syscall_epilogue(const struct syscallname *);
UNUSED static void print_string(abi_long, int);
UNUSED static void print_raw_param(const char *, abi_long, int);
UNUSED static void print_timeval(abi_ulong, int);
UNUSED static void print_number(abi_long, int);
UNUSED static void print_signal(abi_ulong, int);

static void
print_signal(abi_ulong arg, int last)
{
    const char *signal_name = NULL;
    switch(arg) {
    case TARGET_SIGHUP: signal_name = "SIGHUP"; break;
    case TARGET_SIGINT: signal_name = "SIGINT"; break;
    case TARGET_SIGQUIT: signal_name = "SIGQUIT"; break;
    case TARGET_SIGILL: signal_name = "SIGILL"; break;
    case TARGET_SIGABRT: signal_name = "SIGABRT"; break;
    case TARGET_SIGFPE: signal_name = "SIGFPE"; break;
    case TARGET_SIGKILL: signal_name = "SIGKILL"; break;
    case TARGET_SIGSEGV: signal_name = "SIGSEGV"; break;
    case TARGET_SIGPIPE: signal_name = "SIGPIPE"; break;
    case TARGET_SIGALRM: signal_name = "SIGALRM"; break;
    case TARGET_SIGTERM: signal_name = "SIGTERM"; break;
    case TARGET_SIGUSR1: signal_name = "SIGUSR1"; break;
    case TARGET_SIGUSR2: signal_name = "SIGUSR2"; break;
    case TARGET_SIGCHLD: signal_name = "SIGCHLD"; break;
    case TARGET_SIGCONT: signal_name = "SIGCONT"; break;
    case TARGET_SIGSTOP: signal_name = "SIGSTOP"; break;
    case TARGET_SIGTTIN: signal_name = "SIGTTIN"; break;
    case TARGET_SIGTTOU: signal_name = "SIGTTOU"; break;
    }
    if (signal_name == NULL) {
        print_raw_param("%ld", arg, last);
        return;
    }
    gemu_log("%s%s", signal_name, get_comma(last));
}

/*
 * print_xxx utility functions.  These are used to print syscall
 * parameters in certain format.  All of these have parameter
 * named 'last'.  This parameter is used to add comma to output
 * when last == 0.
 */

static const char *
get_comma(int last)
{
    return ((last) ? "" : ",");
}

static void
print_flags(const struct flags *f, abi_long flags, int last)
{
    const char *sep = "";
    int n;

    if ((flags == 0) && (f->f_value == 0)) {
        gemu_log("%s%s", f->f_string, get_comma(last));
        return;
    }
    for (n = 0; f->f_string != NULL; f++) {
        if ((f->f_value != 0) && ((flags & f->f_value) == f->f_value)) {
            gemu_log("%s%s", sep, f->f_string);
            flags &= ~f->f_value;
            sep = "|";
            n++;
        }
    }

    if (n > 0) {
        /* print rest of the flags as numeric */
        if (flags != 0) {
            gemu_log("%s%#x%s", sep, (unsigned int)flags, get_comma(last));
        } else {
            gemu_log("%s", get_comma(last));
        }
    } else {
        /* no string version of flags found, print them in hex then */
        gemu_log("%#x%s", (unsigned int)flags, get_comma(last));
    }
}

static void
print_syscall_prologue(const struct syscallname *sc)
{
    gemu_log("%s(", sc->name);
}

/*ARGSUSED*/
static void
print_syscall_epilogue(const struct syscallname *sc)
{
    (void)sc;
    gemu_log(")");
}

static void
print_string(abi_long addr, int last)
{
    char *s;

    if ((s = lock_user_string(addr)) != NULL) {
        gemu_log("\"%s\"%s", s, get_comma(last));
        unlock_user(s, addr, 0);
    } else {
        /* can't get string out of it, so print it as pointer */
        print_pointer(addr, last);
    }
}

/*
 * Prints out raw parameter using given format.  Caller needs
 * to do byte swapping if needed.
 */
static void
print_raw_param(const char *fmt, abi_long param, int last)
{
    char format[64];

    (void) snprintf(format, sizeof (format), "%s%s", fmt, get_comma(last));
    gemu_log(format, param);
}

static void
print_pointer(abi_long p, int last)
{
    if (p == 0)
        gemu_log("NULL%s", get_comma(last));
    else
        gemu_log("0x" TARGET_ABI_FMT_lx "%s", p, get_comma(last));
}

/*
 * Reads 32-bit (int) number from guest address space from
 * address 'addr' and prints it.
 */
static void
print_number(abi_long addr, int last)
{
    if (addr == 0) {
        gemu_log("NULL%s", get_comma(last));
    } else {
        int num;

        get_user_s32(num, addr);
        gemu_log("[%d]%s", num, get_comma(last));
    }
}

static void
print_timeval(abi_ulong tv_addr, int last)
{
    if( tv_addr ) {
        struct target_timeval *tv;

        tv = lock_user(VERIFY_READ, tv_addr, sizeof(*tv), 1);
        if (!tv)
            return;
        gemu_log("{" TARGET_ABI_FMT_ld "," TARGET_ABI_FMT_ld "}%s",
            tswapal(tv->tv_sec), tswapal(tv->tv_usec), get_comma(last));
        unlock_user(tv, tv_addr, 0);
    } else
        gemu_log("NULL%s", get_comma(last));
}

#undef UNUSED

/*
 * An array of all of the syscalls we know about
 */

static const struct syscallname scnames[] = {
#include "strace.list"
};

static int nsyscalls = ARRAY_SIZE(scnames);

/*
 * The public interface to this module.
 */
void
print_syscall(int num,
              abi_long arg1, abi_long arg2, abi_long arg3,
              abi_long arg4, abi_long arg5, abi_long arg6)
{
    int i;
    const char *format="%s(" TARGET_ABI_FMT_ld "," TARGET_ABI_FMT_ld "," TARGET_ABI_FMT_ld "," TARGET_ABI_FMT_ld "," TARGET_ABI_FMT_ld "," TARGET_ABI_FMT_ld ")";

    gemu_log("%d ", getpid() );

    for(i=0;i<nsyscalls;i++)
        if( scnames[i].nr == num ) {
            if( scnames[i].call != NULL ) {
                scnames[i].call(&scnames[i],arg1,arg2,arg3,arg4,arg5,arg6);
            } else {
                /* XXX: this format system is broken because it uses
                   host types and host pointers for strings */
                if( scnames[i].format != NULL )
                    format = scnames[i].format;
                gemu_log(format,scnames[i].name, arg1,arg2,arg3,arg4,arg5,arg6);
            }
            return;
        }
    gemu_log("Unknown syscall %d\n", num);
}


void
print_syscall_ret(int num, abi_long ret)
{
    int i;
    char *errstr = NULL;

    for(i=0;i<nsyscalls;i++)
        if( scnames[i].nr == num ) {
            if( scnames[i].result != NULL ) {
                scnames[i].result(&scnames[i],ret);
            } else {
                if (ret < 0) {
                    errstr = target_strerror(-ret);
                }
                if (errstr) {
                    gemu_log(" = -1 errno=" TARGET_ABI_FMT_ld " (%s)\n",
                             -ret, errstr);
                } else {
                    gemu_log(" = " TARGET_ABI_FMT_ld "\n", ret);
                }
            }
            break;
        }
}
