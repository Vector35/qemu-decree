/* Code for loading Linux executables.  Mostly linux kernel code.  */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include "qemu.h"

#define NGROUPS 32

/* ??? This should really be somewhere else.  */
abi_long memcpy_to_target(abi_ulong dest, const void *src,
                          unsigned long len)
{
    void *host_ptr;

    host_ptr = lock_user(VERIFY_WRITE, dest, len, 0);
    if (!host_ptr)
        return -TARGET_EFAULT;
    memcpy(host_ptr, src, len);
    unlock_user(host_ptr, dest, 1);
    return 0;
}

static int prepare_binprm(struct linux_binprm *bprm)
{
    struct stat     st;
    int mode;
    int retval;

    if(fstat(bprm->fd, &st) < 0) {
        return(-errno);
    }

    mode = st.st_mode;
    if(!S_ISREG(mode)) {    /* Must be regular file */
        return(-EACCES);
    }
    if(!(mode & 0111)) {    /* Must have at least one execute bit set */
        return(-EACCES);
    }

    bprm->e_uid = geteuid();
    bprm->e_gid = getegid();

    /* Set-uid? */
    if(mode & S_ISUID) {
        bprm->e_uid = st.st_uid;
    }

    /* Set-gid? */
    /*
     * If setgid is set but no group execute bit then this
     * is a candidate for mandatory locking, not a setgid
     * executable.
     */
    if ((mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP)) {
        bprm->e_gid = st.st_gid;
    }

    retval = read(bprm->fd, bprm->buf, BPRM_BUF_SIZE);
    if (retval < 0) {
        perror("prepare_binprm");
        exit(-1);
    }
    if (retval < BPRM_BUF_SIZE) {
        /* Make sure the rest of the loader won't read garbage.  */
        memset(bprm->buf + retval, 0, BPRM_BUF_SIZE - retval);
    }
    return retval;
}

int loader_exec(int fdexec, const char *filename,
             struct target_pt_regs * regs, struct image_info *infop,
             struct linux_binprm *bprm)
{
    int retval;

    bprm->p = 0xbaaab000;
    bprm->fd = fdexec;
    bprm->filename = (char *)filename;

    retval = prepare_binprm(bprm);

    if(retval>=0) {
        if (bprm->buf[0] == 0x7f
                && bprm->buf[1] == 'C'
                && bprm->buf[2] == 'G'
                && bprm->buf[3] == 'C') {
            retval = load_cgc_binary(bprm, infop);
        } else {
            return -ENOEXEC;
        }
    }

    if(retval>=0) {
        /* success.  Initialize important registers */
        do_init_thread(regs, infop);
        return retval;
    }

    return(retval);
}
