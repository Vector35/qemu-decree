/*
 *  Linux syscalls
 *
 *  Copyright (c) 2003 Fabrice Bellard
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
#define _ATFILE_SOURCE
#include "qemu-common.h"
#include "qemu.h"
#include <sys/mman.h>


#define ERRNO_TABLE_SIZE 1200

/* target_to_host_errno_table[] is initialized from
 * host_to_target_errno_table[] in syscall_init(). */
static uint16_t target_to_host_errno_table[ERRNO_TABLE_SIZE] = {
};

/*
 * List of errno mappings for the errors that can be generated by the
 * set of valid DECREE syscalls.
 */
static uint16_t host_to_target_errno_table[ERRNO_TABLE_SIZE] = {
    [EBADF]        = TARGET_EBADF,
    [EFAULT]       = TARGET_EFAULT,
    [EINVAL]       = TARGET_EINVAL,
    [ENOMEM]       = TARGET_ENOMEM,
    [ENOSYS]       = TARGET_ENOSYS,
    [EPIPE]        = TARGET_EPIPE,

    /* This will never be returned directly to the caller and will cause the syscall
     * to be restarted automatically. */
    [EINTR]        = TARGET_EINTR
};

static inline int host_to_target_errno(int err)
{
    if(host_to_target_errno_table[err])
        return host_to_target_errno_table[err];
    return err;
}

static inline int target_to_host_errno(int err)
{
    if (target_to_host_errno_table[err])
        return target_to_host_errno_table[err];
    return err;
}

static inline abi_long get_errno(abi_long ret)
{
    if (ret == -1)
        return -host_to_target_errno(errno);
    else
        return ret;
}

static inline int is_error(abi_long ret)
{
    return (abi_ulong)ret >= (abi_ulong)(-4096);
}

char *target_strerror(int err)
{
    if ((err >= ERRNO_TABLE_SIZE) || (err < 0)) {
        return NULL;
    }
    return strerror(target_to_host_errno(err));
}

void syscall_init(void)
{
    int i;

    /* Build target_to_host_errno_table[] table from
     * host_to_target_errno_table[]. */
    for (i = 0; i < ERRNO_TABLE_SIZE; i++) {
        target_to_host_errno_table[host_to_target_errno_table[i]] = i;
    }
}

static inline abi_long copy_from_user_fdset(fd_set *fds,
                                            abi_ulong target_fds_addr,
                                            int n)
{
    int i, nw, j, k;
    abi_ulong b, *target_fds;

    nw = (n + TARGET_ABI_BITS - 1) / TARGET_ABI_BITS;
    if (!(target_fds = lock_user(VERIFY_READ,
                                 target_fds_addr,
                                 sizeof(abi_ulong) * nw,
                                 1)))
        return -TARGET_EFAULT;

    FD_ZERO(fds);

    if (n > (5 + 2 * binary_count)) {
        // Calculate size for last file descriptor accessible from the guest
        n = 5 + 2 * binary_count;
        nw = (n + TARGET_ABI_BITS - 1) / TARGET_ABI_BITS;
    }

    k = 0;
    for (i = 0; i < nw; i++) {
        /* grab the abi_ulong */
        __get_user(b, &target_fds[i]);
        for (j = 0; j < TARGET_ABI_BITS; j++) {
            /* check the bit inside the abi_ulong */
            if (((b >> j) & 1) && is_valid_guest_fd(k))
                FD_SET(k, fds);
            k++;
        }
    }

    unlock_user(target_fds, target_fds_addr, 0);

    return 0;
}

static inline abi_ulong copy_from_user_fdset_ptr(fd_set *fds, fd_set **fds_ptr,
                                                 abi_ulong target_fds_addr,
                                                 int n)
{
    if (target_fds_addr) {
        if (copy_from_user_fdset(fds, target_fds_addr, n))
            return -TARGET_EFAULT;
        *fds_ptr = fds;
    } else {
        *fds_ptr = NULL;
    }
    return 0;
}

static inline abi_long copy_to_user_fdset(abi_ulong target_fds_addr,
                                          const fd_set *fds,
                                          int n)
{
    int i, nw, j, k;
    abi_long v;
    abi_ulong *target_fds;

    nw = (n + TARGET_ABI_BITS - 1) / TARGET_ABI_BITS;
    if (!(target_fds = lock_user(VERIFY_WRITE,
                                 target_fds_addr,
                                 sizeof(abi_ulong) * nw,
                                 0)))
        return -TARGET_EFAULT;

    k = 0;
    for (i = 0; i < nw; i++) {
        v = 0;
        for (j = 0; j < TARGET_ABI_BITS; j++) {
            if (is_valid_guest_fd(k))
                v |= ((abi_ulong)(FD_ISSET(k, fds) != 0) << j);
            k++;
        }
        __put_user(v, &target_fds[i]);
    }

    unlock_user(target_fds, target_fds_addr, sizeof(abi_ulong) * nw);

    return 0;
}

static inline abi_long copy_from_user_timeval(struct timeval *tv,
                                              abi_ulong target_tv_addr)
{
    struct target_timeval *target_tv;

    if (!lock_user_struct(VERIFY_READ, target_tv, target_tv_addr, 1))
        return -TARGET_EFAULT;

    __get_user(tv->tv_sec, &target_tv->tv_sec);
    __get_user(tv->tv_usec, &target_tv->tv_usec);

    unlock_user_struct(target_tv, target_tv_addr, 0);

    return 0;
}

/* do_select() must return target values and target errnos. */
static abi_long do_select(int n,
                          abi_ulong rfd_addr, abi_ulong wfd_addr,
                          abi_ulong target_tv_addr)
{
    fd_set rfds, wfds;
    fd_set *rfds_ptr, *wfds_ptr;
    struct timeval tv, *tv_ptr;
    abi_long ret;

    ret = copy_from_user_fdset_ptr(&rfds, &rfds_ptr, rfd_addr, n);
    if (ret) {
        return ret;
    }
    ret = copy_from_user_fdset_ptr(&wfds, &wfds_ptr, wfd_addr, n);
    if (ret) {
        return ret;
    }

    if (target_tv_addr) {
        if (copy_from_user_timeval(&tv, target_tv_addr))
            return -TARGET_EFAULT;
        tv_ptr = &tv;
    } else {
        tv_ptr = NULL;
    }

    ret = get_errno(select(n, rfds_ptr, wfds_ptr, NULL, tv_ptr));

    if (!is_error(ret)) {
        if (rfd_addr && copy_to_user_fdset(rfd_addr, &rfds, n))
            return -TARGET_EFAULT;
        if (wfd_addr && copy_to_user_fdset(wfd_addr, &wfds, n))
            return -TARGET_EFAULT;
    }

    return ret;
}

/* do_syscall() should always have a single exit point at the end so
   that actions, such as logging of syscall results, can be performed.
   All errnos that do_syscall() returns must be -TARGET_<errcode>. */
abi_long do_syscall(void *cpu_env, int num, abi_long arg1,
                    abi_long arg2, abi_long arg3, abi_long arg4,
                    abi_long arg5, abi_long arg6)
{
    /* CPUState *cpu = ENV_GET_CPU(cpu_env); */
    abi_long ret;
    abi_ulong i;
    void *p;

#ifdef DEBUG
    gemu_log("syscall %d", num);
#endif
    if(do_strace)
        print_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6);

    switch(num) {
    case 1: /* terminate */
        replay_close();
        _exit(arg1);
        ret = 0; /* avoid warning */
        break;

    case 2: /* transmit */
        if (!is_valid_guest_fd(arg1)) {
            ret = -TARGET_EBADF;
            break;
        }

        /* Because DECREE binaries are usually connected to a network socket, file descriptors
           0 and 1 (stdin/stdout) are typically pointing at the same file object.  Some
           challenge binaries violate the stdin/stdout standard and use the wrong descriptor
           to transmit or receive.  Fix this up here so that binaries will run the same way
           independent of whether they are going to stdin/stdout or a network socket. */
        if (arg1 == 0)
            arg1 = 1;

        if (!(p = lock_user(VERIFY_READ, arg2, arg3, 1)))
            goto efault;

        if (is_replaying()) {
            /* Replaying, read and verify replay event */
            struct replay_event evt;
            void* data;

            data = read_replay_event(&evt);
            if ((evt.event_id != REPLAY_EVENT_TRANSMIT) || (evt.fd != arg1)) {
                fprintf(stderr, "Replay event mismatch at index %d\n", evt.global_ordering);
                abort();
            }

            ret = evt.result;

            if ((ret > 0) && (ret > arg3)) {
                fprintf(stderr, "Replay length too large at index %d\n", evt.global_ordering);
                abort();
            }

            if ((ret > 0) && replay_has_validation()) {
                /* Validate that the data being sent matches the original execution */
                if (evt.data_length < ret) {
                    fprintf(stderr, "Data missing from replay event at index %d\n", evt.global_ordering);
                    abort();
                }

                if (memcmp(data, p, ret) != 0) {
                    fprintf(stderr, "Replay transmit data mismatch at index %d\n", evt.global_ordering);
                    abort();
                }
            }

            free_replay_event(data);
        } else {
            /* Normal execution */
            replay_begin_event();
            ret = get_errno(write(arg1, p, arg3));

            if (ret <= 0)
                replay_write_event(REPLAY_EVENT_TRANSMIT, arg1, ret);
            else
                replay_write_event_with_validation_data(REPLAY_EVENT_TRANSMIT, arg1, ret, p, ret);
        }

        unlock_user(p, arg2, 0);
        if (!is_error(ret)) {
            if (arg4 && put_user_sal(ret, arg4))
                goto efault;
            ret = 0;
        }

        /* In the game environment stdin/stdout are always on a socket, but during simulation
         * it may be a pipe.  Redirect any EPIPE errors to EINVAL to mirror what would happen
         * on a socket. */
        if ((arg1 == 1) && (ret == -TARGET_EPIPE))
            ret = -TARGET_EINVAL;
        break;

    case 3: /* receive */
        if (!is_valid_guest_fd(arg1)) {
            ret = -TARGET_EBADF;
            break;
        }

        /* Because DECREE binaries are usually connected to a network socket, file descriptors
           0 and 1 (stdin/stdout) are typically pointing at the same file object.  Some
           challenge binaries violate the stdin/stdout standard and use the wrong descriptor
           to transmit or receive.  Fix this up here so that binaries will run the same way
           independent of whether they are going to stdin/stdout or a network socket. */
        if (arg1 == 1)
            arg1 = 0;

        if (!(p = lock_user(VERIFY_WRITE, arg2, arg3, 0)))
            goto efault;

        if (is_replaying()) {
            /* Replaying, read and verify replay event */
            struct replay_event evt;
            void* data;

            data = read_replay_event(&evt);
            if ((evt.event_id != REPLAY_EVENT_RECEIVE) || (evt.fd != arg1)) {
                fprintf(stderr, "Replay event mismatch at index %d\n", evt.global_ordering);
                abort();
            }

            ret = evt.result;

            if ((ret > 0) && (ret > arg3)) {
                fprintf(stderr, "Replay length too large at index %d\n", evt.global_ordering);
                abort();
            }

            if (ret > 0) {
                if (evt.data_length < ret) {
                    fprintf(stderr, "Data missing from replay event at index %d\n", evt.global_ordering);
                    abort();
                }

                /* Grab the data from the original execution to complete the read */
                memcpy(p, data, ret);
            }

            free_replay_event(data);
        } else {
            /* Normal execution */
            replay_begin_event();
            if (arg3 == 0)
                ret = 0;
            else
                ret = get_errno(read(arg1, p, arg3));

            if (ret <= 0)
                replay_write_event(REPLAY_EVENT_RECEIVE, arg1, ret);
            else
                replay_write_event_with_required_data(REPLAY_EVENT_RECEIVE, arg1, ret, p, ret);
        }

        unlock_user(p, arg2, (ret < 0) ? 0 : ret);

        if (!is_error(ret)) {
            if (arg4 && put_user_sal(ret, arg4))
                goto efault;
            ret = 0;
        }

        /* In the game environment stdin/stdout are always on a socket, but during simulation
         * it may be a pipe.  Redirect any EPIPE errors to EINVAL to mirror what would happen
         * on a socket. */
        if ((arg1 == 0) && (ret == -TARGET_EPIPE))
            ret = -TARGET_EINVAL;
        break;

    case 4: /* fdwait */
        if (is_replaying()) {
            /* Replaying, read and verify replay event */
            struct replay_event evt;
            uint32_t* data;

            data = (uint32_t*)read_replay_event(&evt);
            if ((evt.event_id != REPLAY_EVENT_FDWAIT) || (evt.fd != arg1)) {
                fprintf(stderr, "Replay event mismatch at index %d\n", evt.global_ordering);
                abort();
            }

            ret = evt.result;

            if (ret >= 0) {
                /* Grab the fdset state from the original execution to complete the syscall */
                int nw, n = arg1;
                int full_words;

                full_words = (n + 31) / 32;

                if (n > (4 + binary_count * 2)) {
                    n = 4 + binary_count * 2;
                }
                nw = (n + 31) / 32;

                if (evt.data_length < (sizeof(uint32_t) * nw * 2)) {
                    fprintf(stderr, "Data missing from replay event at index %d\n", evt.global_ordering);
                    abort();
                }

                for (i = 0; i < nw; i++) {
                    if (arg2 != 0) {
                        put_user_u32(data[i], arg2 + (i * 4));
                    }
                    if (arg3 != 0) {
                        put_user_u32(data[i + nw], arg3 + (i * 4));
                    }
                }

                for (i = nw; i < full_words; i++) {
                    if (arg2 != 0) {
                        put_user_u32(0, arg2 + (i * 4));
                    }
                    if (arg3 != 0) {
                        put_user_u32(0, arg3 + (i * 4));
                    }
                }
            }

            free_replay_event(data);
        } else {
            /* Normal execution */
            replay_begin_event();
            ret = do_select(arg1, arg2, arg3, arg4);

            if (ret < 0) {
                replay_write_event(REPLAY_EVENT_FDWAIT, arg1, ret);
            } else {
                /* Need to record read/write status from the guest, as this isn't deterministic. */
                int nw, n = arg1;
                uint32_t* data;
                if (n > (4 + binary_count * 2)) {
                    n = 4 + binary_count * 2;
                }
                nw = (n + 31) / 32;

                data = (uint32_t*)alloca(sizeof(uint32_t) * nw * 2);
                memset(data, 0, sizeof(uint32_t) * nw * 2);

                for (i = 0; i < nw; i++) {
                    if (arg2 != 0) {
                        get_user_u32(data[i], arg2 + (i * 4));
                    }
                    if (arg3 != 0) {
                        get_user_u32(data[i + nw], arg3 + (i * 4));
                    }
                }

                replay_write_event_with_required_data(REPLAY_EVENT_FDWAIT, arg1, ret, data, sizeof(uint32_t) * nw * 2);
            }
        }

        if (ret >= 0) {
            if (arg5 && put_user_sal(ret, arg5))
                goto efault;
            ret = 0;
        }
        break;

    case 5: /* allocate */
        if (!access_ok(VERIFY_WRITE, arg3, sizeof(abi_long)))
            goto efault;
        ret = get_errno(target_mmap(0, arg1, PROT_READ | PROT_WRITE | (arg2 ? PROT_EXEC: 0),
                                    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0));
        if (!is_error(ret)) {
            if (put_user_sal(ret, arg3))
                goto efault;
            ret = 0;
        }
        break;

    case 6: /* deallocate */
        ret = get_errno(target_munmap(arg1, arg2));
        break;

    case 7: /* random */
        if (!(p = lock_user(VERIFY_WRITE, arg1, arg2, 0)))
            goto efault;
        for (i = 0; i < (abi_ulong)arg2; i++) {
            /* FIXME: Use same random algorithm as DARPA kernel */
            ((char*)p)[i] = (char)(rand() & 0xff);
        }

        if (is_replaying()) {
            /* Replaying, read and verify replay event */
            if (replay_has_validation()) {
                struct replay_event evt;
                void* data;

                data = read_replay_event(&evt);
                if (evt.event_id != REPLAY_EVENT_RANDOM) {
                    fprintf(stderr, "Replay event mismatch at index %d\n", evt.global_ordering);
                    abort();
                }

                if (evt.result != arg2) {
                    fprintf(stderr, "Replay length mismatch at index %d\n", evt.global_ordering);
                    abort();
                }

                if (evt.data_length < arg2) {
                    fprintf(stderr, "Data missing from replay event at index %d\n", evt.global_ordering);
                    abort();
                }

                /* Validate that random data matches original execution */
                if (memcmp(data, p, arg2) != 0) {
                    fprintf(stderr, "Replay random data mismatch at index %d\n", evt.global_ordering);
                    abort();
                }

                free_replay_event(data);
            }
        } else {
            /* Normal execution */
            replay_nonblocking_event();
            replay_write_validation_event(REPLAY_EVENT_RANDOM, 0, arg2, p, arg2);
        }

        unlock_user(p, arg1, arg2);
        if (arg3 && put_user_sal(arg2, arg3))
            goto efault;
        ret = 0;
        break;

    default:
        gemu_log("qemu: Unsupported syscall: %d\n", num);
        ret = -TARGET_ENOSYS;
        break;
    }
fail:
#ifdef DEBUG
    gemu_log(" = " TARGET_ABI_FMT_ld "\n", ret);
#endif
    if(do_strace)
        print_syscall_ret(num, ret, arg1, arg2, arg3, arg4, arg5, arg6);
    /* Errors returned to the guest should be positive integers */
    return -ret;
efault:
    ret = -TARGET_EFAULT;
    goto fail;
}
