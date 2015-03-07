/*
 * Target definitions of errnos.
 */
#define TARGET_EBADF            1      /* Bad file number */
#define TARGET_EFAULT           2      /* Bad address */
#define TARGET_EINVAL           3      /* Invalid argument */
#define TARGET_ENOMEM           4      /* Out of memory */
#define TARGET_ENOSYS           5      /* Function not implemented */
#define TARGET_EPIPE            6      /* Broken pipe */

/* EINTR is never returned to the guest, and is only uesd to automatically
 * restart the syscall internally. */
#define TARGET_EINTR            255
