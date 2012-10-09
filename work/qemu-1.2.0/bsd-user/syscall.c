/*
 *  BSD syscalls
 *
 *  Copyright (c) 2003 - 2008 Fabrice Bellard
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
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <sys/event.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <utime.h>

#include <netinet/in.h>

#include "qemu.h"
#include "qemu-common.h"

//#define DEBUG

static abi_ulong target_brk;
static abi_ulong target_original_brk;

static inline abi_long get_errno(abi_long ret)
{
    if (ret == -1)
        /* XXX need to translate host -> target errnos here */
        return -(errno);
    else
        return ret;
}

static inline int
host_to_target_errno(int err)
{
	/* XXX need to translate host errnos here */
	return (err);
}

#define target_to_host_bitmask(x, tbl) (x)

static inline int is_error(abi_long ret)
{
    return (abi_ulong)ret >= (abi_ulong)(-4096);
}

void target_set_brk(abi_ulong new_brk)
{
    target_original_brk = target_brk = HOST_PAGE_ALIGN(new_brk);
}

/* do_obreak() must return target errnos. */
static abi_long do_obreak(abi_ulong new_brk)
{
    abi_ulong brk_page;
    abi_long mapped_addr;
    int new_alloc_size;

    if (!new_brk)
        return 0;
    if (new_brk < target_original_brk)
        return -TARGET_EINVAL;

    brk_page = HOST_PAGE_ALIGN(target_brk);

    /* If the new brk is less than this, set it and we're done... */
    if (new_brk < brk_page) {
        target_brk = new_brk;
        return 0;
    }

    /* We need to allocate more memory after the brk... */
    new_alloc_size = HOST_PAGE_ALIGN(new_brk - brk_page + 1);
    mapped_addr = get_errno(target_mmap(brk_page, new_alloc_size,
                                        PROT_READ|PROT_WRITE,
                                        MAP_ANON|MAP_FIXED|MAP_PRIVATE, -1, 0));

    if (!is_error(mapped_addr))
        target_brk = new_brk;
    else
        return mapped_addr;

    return 0;
}

abi_long do_brk(abi_ulong new_brk)
{
    return do_obreak(new_brk);
}

#if defined(TARGET_I386)
static abi_long do_freebsd_sysarch(CPUX86State *env, int op, abi_ulong parms)
{
    abi_long ret = 0;
    abi_ulong val;
    int idx;

    switch(op) {
#ifdef TARGET_ABI32
    case TARGET_FREEBSD_I386_SET_GSBASE:
    case TARGET_FREEBSD_I386_SET_FSBASE:
        if (op == TARGET_FREEBSD_I386_SET_GSBASE)
#else
    case TARGET_FREEBSD_AMD64_SET_GSBASE:
    case TARGET_FREEBSD_AMD64_SET_FSBASE:
        if (op == TARGET_FREEBSD_AMD64_SET_GSBASE)
#endif
            idx = R_GS;
        else
            idx = R_FS;
        if (get_user(val, parms, abi_ulong))
            return -TARGET_EFAULT;
        cpu_x86_load_seg(env, idx, 0);
        env->segs[idx].base = val;
        break;
#ifdef TARGET_ABI32
    case TARGET_FREEBSD_I386_GET_GSBASE:
    case TARGET_FREEBSD_I386_GET_FSBASE:
        if (op == TARGET_FREEBSD_I386_GET_GSBASE)
#else
    case TARGET_FREEBSD_AMD64_GET_GSBASE:
    case TARGET_FREEBSD_AMD64_GET_FSBASE:
        if (op == TARGET_FREEBSD_AMD64_GET_GSBASE)
#endif
            idx = R_GS;
        else
            idx = R_FS;
        val = env->segs[idx].base;
        if (put_user(val, parms, abi_ulong))
            return -TARGET_EFAULT;
        break;
    /* XXX handle the others... */
    default:
        ret = -TARGET_EINVAL;
        break;
    }
    return ret;
}
#endif

#ifdef TARGET_SPARC
static abi_long do_freebsd_sysarch(void *env, int op, abi_ulong parms)
{
    /* XXX handle
     * TARGET_FREEBSD_SPARC_UTRAP_INSTALL,
     * TARGET_FREEBSD_SPARC_SIGTRAMP_INSTALL
     */
    return -TARGET_EINVAL;
}
#endif

#ifdef TARGET_ARM
static abi_long do_freebsd_sysarch(void *env, int op, abi_ulong parms)
{
    return -TARGET_EINVAL;
}
#endif

#ifdef TARGET_MIPS
static abi_long do_freebsd_sysarch(void *env, int op, abi_ulong parms)
{
    return -TARGET_EINVAL;
}
#endif

#ifdef __FreeBSD__
/*
 * XXX this uses the undocumented oidfmt interface to find the kind of
 * a requested sysctl, see /sys/kern/kern_sysctl.c:sysctl_sysctl_oidfmt()
 * (this is mostly copied from src/sbin/sysctl/sysctl.c)
 */
static int
oidfmt(int *oid, int len, char *fmt, uint32_t *kind)
{
    int qoid[CTL_MAXNAME+2];
    uint8_t buf[BUFSIZ];
    int i;
    size_t j;

    qoid[0] = 0;
    qoid[1] = 4;
    memcpy(qoid + 2, oid, len * sizeof(int));

    j = sizeof(buf);
    i = sysctl(qoid, len + 2, buf, &j, 0, 0);
    if (i)
        return i;

    if (kind)
        *kind = *(uint32_t *)buf;

    if (fmt)
        strcpy(fmt, (char *)(buf + sizeof(uint32_t)));
    return (0);
}

/*
 * try and convert sysctl return data for the target.
 * XXX doesn't handle CTLTYPE_OPAQUE and CTLTYPE_STRUCT.
 */
static int sysctl_oldcvt(void *holdp, size_t holdlen, uint32_t kind)
{
    switch (kind & CTLTYPE) {
    case CTLTYPE_INT:
    case CTLTYPE_UINT:
        *(uint32_t *)holdp = tswap32(*(uint32_t *)holdp);
        break;
#ifdef TARGET_ABI32
    case CTLTYPE_LONG:
    case CTLTYPE_ULONG:
        *(uint32_t *)holdp = tswap32(*(long *)holdp);
        break;
#else
    case CTLTYPE_LONG:
        *(uint64_t *)holdp = tswap64(*(long *)holdp);
    case CTLTYPE_ULONG:
        *(uint64_t *)holdp = tswap64(*(unsigned long *)holdp);
        break;
#endif
#if !defined(__FreeBSD_version) || __FreeBSD_version < 900031
    case CTLTYPE_QUAD:
#else
    case CTLTYPE_U64:
    case CTLTYPE_S64:
#endif
        *(uint64_t *)holdp = tswap64(*(uint64_t *)holdp);
        break;
    case CTLTYPE_STRING:
        break;
    default:
        /* XXX unhandled */
        return -1;
    }
    return 0;
}

/* XXX this needs to be emulated on non-FreeBSD hosts... */
static abi_long do_freebsd_sysctl(abi_ulong namep, int32_t namelen, abi_ulong oldp,
                          abi_ulong oldlenp, abi_ulong newp, abi_ulong newlen)
{
    abi_long ret;
    void *hnamep, *holdp, *hnewp = NULL;
    size_t holdlen;
    abi_ulong oldlen = 0;
    int32_t *snamep = g_malloc(sizeof(int32_t) * namelen), *p, *q, i;
    uint32_t kind = 0;

    if (oldlenp)
        get_user_ual(oldlen, oldlenp);
    if (!(hnamep = lock_user(VERIFY_READ, namep, namelen, 1)))
        return -TARGET_EFAULT;
    if (newp && !(hnewp = lock_user(VERIFY_READ, newp, newlen, 1)))
        return -TARGET_EFAULT;
    if (!(holdp = lock_user(VERIFY_WRITE, oldp, oldlen, 0)))
        return -TARGET_EFAULT;
    holdlen = oldlen;
    for (p = hnamep, q = snamep, i = 0; i < namelen; p++, i++)
       *q++ = tswap32(*p);
    oidfmt(snamep, namelen, NULL, &kind);
    /* XXX swap hnewp */
    ret = get_errno(sysctl(snamep, namelen, holdp, &holdlen, hnewp, newlen));
    if (!ret)
        sysctl_oldcvt(holdp, holdlen, kind);
    put_user_ual(holdlen, oldlenp);
    unlock_user(hnamep, namep, 0);
    unlock_user(holdp, oldp, holdlen);
    if (hnewp)
        unlock_user(hnewp, newp, 0);
    g_free(snamep);
    return ret;
}
#endif

/* FIXME
 * lock_iovec()/unlock_iovec() have a return code of 0 for success where
 * other lock functions have a return code of 0 for failure.
 */
static abi_long lock_iovec(int type, struct iovec *vec, abi_ulong target_addr,
                           int count, int copy)
{
    struct target_iovec *target_vec;
    abi_ulong base;
    int i;

    target_vec = lock_user(VERIFY_READ, target_addr, count * sizeof(struct target_iovec), 1);
    if (!target_vec)
        return -TARGET_EFAULT;
    for(i = 0;i < count; i++) {
        base = tswapl(target_vec[i].iov_base);
        vec[i].iov_len = tswapl(target_vec[i].iov_len);
        if (vec[i].iov_len != 0) {
            vec[i].iov_base = lock_user(type, base, vec[i].iov_len, copy);
            /* Don't check lock_user return value. We must call writev even
               if a element has invalid base address. */
        } else {
            /* zero length pointer is ignored */
            vec[i].iov_base = NULL;
        }
    }
    unlock_user (target_vec, target_addr, 0);
    return 0;
}

static abi_long unlock_iovec(struct iovec *vec, abi_ulong target_addr,
                             int count, int copy)
{
    struct target_iovec *target_vec;
    abi_ulong base;
    int i;

    target_vec = lock_user(VERIFY_READ, target_addr, count * sizeof(struct target_iovec), 1);
    if (!target_vec)
        return -TARGET_EFAULT;
    for(i = 0;i < count; i++) {
        if (target_vec[i].iov_base) {
            base = tswapl(target_vec[i].iov_base);
            unlock_user(vec[i].iov_base, base, copy ? vec[i].iov_len : 0);
        }
    }
    unlock_user (target_vec, target_addr, 0);

    return 0;
}

static inline abi_long
target_to_host_sockaddr(struct sockaddr *addr, abi_ulong target_addr,
    socklen_t len)
{
	const socklen_t unix_maxlen = sizeof (struct sockaddr_un);
	sa_family_t sa_family;
	struct target_sockaddr *target_saddr;

	target_saddr = lock_user(VERIFY_READ, target_addr, len, 1);
	if (!target_saddr)
		return -TARGET_EFAULT;

	sa_family = tswap16(target_saddr->sa_family);

	/*
	 * Oops. The caller might send a incomplete sun_path; sun_path
	 * must be terminated by \0 (see the manual page), but unfortunately
	 * it is quite common to specify sockaddr_un length as
	 * "strlen(x->sun_path)" while it should be "strlen(...) + 1". We will
	 * fix that here if needed.
	 */
	if (sa_family == AF_UNIX) {
		if (len < unix_maxlen && len > 0) {
			char *cp = (char*)target_saddr;

			if ( cp[len-1] && !cp[len] )
				len++;
		}
		if (len > unix_maxlen)
			len = unix_maxlen;
	}

	memcpy(addr, target_saddr, len);
	addr->sa_family = sa_family;
	unlock_user(target_saddr, target_addr, 0);

	return (0);
}

static inline abi_long
host_to_target_sockaddr(abi_ulong target_addr, struct sockaddr *addr,
    socklen_t len)
{
	struct target_sockaddr *target_saddr;

	target_saddr = lock_user(VERIFY_WRITE, target_addr, len, 0);
	if (!target_saddr)
		return (-TARGET_EFAULT);
	memcpy(target_saddr, addr, len);
	target_saddr->sa_family = tswap16(addr->sa_family);
	unlock_user(target_saddr, target_addr, len);

	return (0);
}

static inline abi_long
target_to_host_cmsg(struct msghdr *msgh, struct target_msghdr *target_msgh)
{
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(msgh);
	abi_long msg_controllen;
	abi_ulong target_cmsg_addr;
	struct target_cmsghdr *target_cmsg;
	socklen_t space = 0;


	msg_controllen = tswapal(target_msgh->msg_controllen);
	if (msg_controllen < sizeof (struct target_cmsghdr))
		goto the_end;
	target_cmsg_addr = tswapal(target_msgh->msg_control);
	target_cmsg = lock_user(VERIFY_READ, target_cmsg_addr,
	    msg_controllen, 1);
	if (!target_cmsg)
		return (-TARGET_EFAULT);
	while (cmsg && target_cmsg) {
		void *data = CMSG_DATA(cmsg);
		void *target_data = TARGET_CMSG_DATA(target_cmsg);
		int len = tswapal(target_cmsg->cmsg_len) -
		    TARGET_CMSG_ALIGN(sizeof (struct target_cmsghdr));
		space += CMSG_SPACE(len);
		if (space > msgh->msg_controllen) {
			space -= CMSG_SPACE(len);
			gemu_log("Host cmsg overflow\n");
			break;
		}
		cmsg->cmsg_level = tswap32(target_cmsg->cmsg_level);
		cmsg->cmsg_type = tswap32(target_cmsg->cmsg_type);
		cmsg->cmsg_len = CMSG_LEN(len);

		if (cmsg->cmsg_level != TARGET_SOL_SOCKET ||
		    cmsg->cmsg_type != SCM_RIGHTS) {
			gemu_log("Unsupported ancillary data: %d/%d\n",
			    cmsg->cmsg_level, cmsg->cmsg_type);
			memcpy(data, target_data, len);
		} else {
			int *fd = (int *)data;
			int *target_fd = (int *)target_data;
			int i, numfds = len / sizeof(int);

			for (i = 0; i < numfds; i++)
				fd[i] = tswap32(target_fd[i]);
		}
		cmsg = CMSG_NXTHDR(msgh, cmsg);
		target_cmsg = TARGET_CMSG_NXTHDR(target_msgh, target_cmsg);
	}
	unlock_user(target_cmsg, target_cmsg_addr, 0);

the_end:
	msgh->msg_controllen = space;
	return (0);
}

static inline abi_long
host_to_target_cmsg(struct target_msghdr *target_msgh, struct msghdr *msgh)
{
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(msgh);
	abi_long msg_controllen;
	abi_ulong target_cmsg_addr;
	struct target_cmsghdr *target_cmsg;
	socklen_t space = 0;

	msg_controllen = tswapal(target_msgh->msg_controllen);
	if (msg_controllen < sizeof (struct target_cmsghdr))
		goto the_end;
	target_cmsg_addr = tswapal(target_msgh->msg_control);
	target_cmsg = lock_user(VERIFY_WRITE, target_cmsg_addr,
	    msg_controllen, 0);
	if (!target_cmsg)
		return (-TARGET_EFAULT);
	while (cmsg && target_cmsg) {
		void *data = CMSG_DATA(cmsg);
		void *target_data = TARGET_CMSG_DATA(target_cmsg);
		int len = cmsg->cmsg_len - CMSG_ALIGN(sizeof (struct cmsghdr));

		space += TARGET_CMSG_SPACE(len);
		if (space > msg_controllen) {
			space -= TARGET_CMSG_SPACE(len);
			gemu_log("Target cmsg overflow\n");
			break;
		}
		target_cmsg->cmsg_level = tswap32(cmsg->cmsg_level);
		target_cmsg->cmsg_type = tswap32(cmsg->cmsg_type);
		target_cmsg->cmsg_len = tswapal(TARGET_CMSG_LEN(len));
		if ((cmsg->cmsg_level == TARGET_SOL_SOCKET) &&
		    (cmsg->cmsg_type == SCM_RIGHTS)) {
			int *fd = (int *)data;
			int *target_fd = (int *)target_data;
			int i, numfds = len / sizeof(int);
			for (i = 0; i < numfds; i++)
				target_fd[i] = tswap32(fd[i]);
		} else if ((cmsg->cmsg_level == TARGET_SOL_SOCKET) &&
		    (cmsg->cmsg_type == SO_TIMESTAMP) &&
		    (len == sizeof(struct timeval))) {
			/* copy struct timeval to target */
			struct timeval *tv = (struct timeval *)data;
			struct target_timeval *target_tv =
			    (struct target_timeval *)target_data;
			target_tv->tv_sec = tswapal(tv->tv_sec);
			target_tv->tv_usec = tswapal(tv->tv_usec);
		} else {
			gemu_log("Unsupported ancillary data: %d/%d\n",
			    cmsg->cmsg_level, cmsg->cmsg_type);
			memcpy(target_data, data, len);
		}
		cmsg = CMSG_NXTHDR(msgh, cmsg);
		target_cmsg = TARGET_CMSG_NXTHDR(target_msgh, target_cmsg);
	}
	unlock_user(target_cmsg, target_cmsg_addr, space);

the_end:
	target_msgh->msg_controllen = tswapal(space);
	return (0);
}

static inline rlim_t
target_to_host_rlim(abi_ulong target_rlim)
{
	abi_ulong target_rlim_swap;
	rlim_t result;

	target_rlim_swap = tswapal(target_rlim);
	if (target_rlim_swap == TARGET_RLIM_INFINITY)
		return (RLIM_INFINITY);

	result = target_rlim_swap;
	if (target_rlim_swap != (rlim_t)result)
		return (RLIM_INFINITY);

	return (result);
}

static inline abi_ulong
host_to_target_rlim(rlim_t rlim)
{
	abi_ulong target_rlim_swap;
	abi_ulong result;

	if (rlim == RLIM_INFINITY || rlim != (abi_long)rlim)
		target_rlim_swap = TARGET_RLIM_INFINITY;
	else
		target_rlim_swap = rlim;
	result = tswapal(target_rlim_swap);

	return (result);
}

static inline int
target_to_host_resource(int code)
{

	switch (code) {
	case TARGET_RLIMIT_AS:
		return RLIMIT_AS;

	case TARGET_RLIMIT_CORE:
		return RLIMIT_CORE;

	case TARGET_RLIMIT_CPU:
		return RLIMIT_CPU;

	case TARGET_RLIMIT_DATA:
		return RLIMIT_DATA;

	case TARGET_RLIMIT_FSIZE:
		return RLIMIT_FSIZE;

	case TARGET_RLIMIT_MEMLOCK:
		return RLIMIT_MEMLOCK;

	case TARGET_RLIMIT_NOFILE:
		return RLIMIT_NOFILE;

	case TARGET_RLIMIT_NPROC:
		return RLIMIT_NPROC;

	case TARGET_RLIMIT_RSS:
		return RLIMIT_RSS;

	case TARGET_RLIMIT_SBSIZE:
		return RLIMIT_SBSIZE;

	case TARGET_RLIMIT_STACK:
		return RLIMIT_STACK;

	case TARGET_RLIMIT_SWAP:
		return RLIMIT_SWAP;

	case TARGET_RLIMIT_NPTS:
		return RLIMIT_NPTS;

	default:
		return (code);
	}
}

static int
target_to_host_fcntl_cmd(int cmd)
{

	switch(cmd) {
	case TARGET_F_DUPFD:
		return F_DUPFD;

	case TARGET_F_DUP2FD:
		return F_DUP2FD;

	case TARGET_F_GETFD:
		return F_GETFD;

	case TARGET_F_SETFD:
		return F_SETFD;

	case TARGET_F_GETFL:
		return F_GETFL;

	case TARGET_F_SETFL:
		return F_SETFL;

	case TARGET_F_GETOWN:
		return F_GETOWN;

	case TARGET_F_SETOWN:
		return F_SETOWN;

	case TARGET_F_GETLK:
		return F_GETLK;

	case TARGET_F_SETLK:
		return F_SETLK;

	case TARGET_F_SETLKW:
		return F_SETLKW;

	case TARGET_F_READAHEAD:
		return F_READAHEAD;

	case TARGET_F_RDAHEAD:
		return F_RDAHEAD;

	default:
		return (cmd);
	}
}

static inline abi_long
host_to_target_rusage(abi_ulong target_addr, const struct rusage *rusage)
{
	struct target_rusage *target_rusage;

	if (!lock_user_struct(VERIFY_WRITE, target_rusage, target_addr, 0))
		return (-TARGET_EFAULT);
	target_rusage->ru_utime.tv_sec = tswapal(rusage->ru_utime.tv_sec);
	target_rusage->ru_utime.tv_usec = tswapal(rusage->ru_utime.tv_usec);
	target_rusage->ru_stime.tv_sec = tswapal(rusage->ru_stime.tv_sec);
	target_rusage->ru_stime.tv_usec = tswapal(rusage->ru_stime.tv_usec);
	target_rusage->ru_maxrss = tswapal(rusage->ru_maxrss);
	target_rusage->ru_ixrss = tswapal(rusage->ru_ixrss);
	target_rusage->ru_idrss = tswapal(rusage->ru_idrss);
	target_rusage->ru_isrss = tswapal(rusage->ru_isrss);
	target_rusage->ru_minflt = tswapal(rusage->ru_minflt);
	target_rusage->ru_majflt = tswapal(rusage->ru_majflt);
	target_rusage->ru_nswap = tswapal(rusage->ru_nswap);
	target_rusage->ru_inblock = tswapal(rusage->ru_inblock);
	target_rusage->ru_oublock = tswapal(rusage->ru_oublock);
	target_rusage->ru_msgsnd = tswapal(rusage->ru_msgsnd);
	target_rusage->ru_msgrcv = tswapal(rusage->ru_msgrcv);
	target_rusage->ru_nsignals = tswapal(rusage->ru_nsignals);
	target_rusage->ru_nvcsw = tswapal(rusage->ru_nvcsw);
	target_rusage->ru_nivcsw = tswapal(rusage->ru_nivcsw);
	unlock_user_struct(target_rusage, target_addr, 1);

	return (0);
}

/*
 * Map host to target signal numbers for the wait family of syscalls.
 * Assume all other status bits are the same.
 */
static int
host_to_target_waitstatus(int status)
{
	if (WIFSIGNALED(status)) {
		return (host_to_target_signal(WTERMSIG(status)) |
		    (status & ~0x7f));
	}
	if (WIFSTOPPED(status)) {
		return (host_to_target_signal(WSTOPSIG(status)) << 8) |
		    (status & 0xff);
	}
	return (status);
}

static inline abi_long
fbsd_copy_from_user_timeval(struct timeval *tv, abi_ulong target_tv_addr)
{
     struct target_freebsd_timeval *target_tv;

     if (!lock_user_struct(VERIFY_READ, target_tv, target_tv_addr, 0))
		return -TARGET_EFAULT;
   __get_user(tv->tv_sec, &target_tv->tv_sec);
   __get_user(tv->tv_usec, &target_tv->tv_usec);
     unlock_user_struct(target_tv, target_tv_addr, 1);
     return (0);
}

static inline abi_long
target_to_host_timespec(struct timespec *ts, abi_ulong target_ts_addr)
{
     struct target_freebsd_timespec *target_ts;

     if (!lock_user_struct(VERIFY_READ, target_ts, target_ts_addr, 0))
		return -TARGET_EFAULT;
   __get_user(ts->tv_sec, &target_ts->tv_sec);
   __get_user(ts->tv_nsec, &target_ts->tv_nsec);
     unlock_user_struct(target_ts, target_ts_addr, 1);
     return (0);
}

static inline abi_long
fbsd_copy_to_user_timeval(struct timeval *tv, abi_ulong target_tv_addr)
{
     struct target_freebsd_timeval *target_tv;

     if (!lock_user_struct(VERIFY_WRITE, target_tv, target_tv_addr, 0))
		return -TARGET_EFAULT;
   __put_user(tv->tv_sec, &target_tv->tv_sec);
   __put_user(tv->tv_usec, &target_tv->tv_usec);
     unlock_user_struct(target_tv, target_tv_addr, 1);
     return (0);
}

static inline abi_long
host_to_target_timespec(abi_ulong target_ts_addr, struct timespec *ts)
{
     struct target_freebsd_timespec *target_ts;

     if (!lock_user_struct(VERIFY_WRITE, target_ts, target_ts_addr, 0))
		return -TARGET_EFAULT;
   __put_user(ts->tv_sec, &target_ts->tv_sec);
   __put_user(ts->tv_nsec, &target_ts->tv_nsec);
     unlock_user_struct(target_ts, target_ts_addr, 1);
     return (0);
}
static inline abi_ulong
fbsd_copy_from_user_fdset(fd_set *fds, abi_ulong target_fds_addr, int n)
{
	int i, nw, j, k;
	abi_ulong b, *target_fds;

	nw = (n + TARGET_ABI_BITS - 1) / TARGET_ABI_BITS;
	if (!(target_fds = lock_user(VERIFY_READ, target_fds_addr,
		    sizeof(abi_ulong) * nw, 1)))
		return (-TARGET_EFAULT);

	FD_ZERO(fds);
	k = 0;
	for (i = 0; i < nw; i++) {
		/* grab the abi_ulong */
		__get_user(b, &target_fds[i]);
		for (j = 0; j < TARGET_ABI_BITS; j++) {
			/* check the bit inside the abi_ulong */
			if ((b >> j) & 1)
				FD_SET(k, fds);
			k++;
		}
	}

	unlock_user(target_fds, target_fds_addr, 0);

	return (0);
}

static inline abi_ulong
fbsd_copy_from_user_fdset_ptr(fd_set *fds, fd_set **fds_ptr,
    abi_ulong target_fds_addr, int n)
{
	if (target_fds_addr) {
		if (fbsd_copy_from_user_fdset(fds, target_fds_addr, n))
			return (-TARGET_EFAULT);
		*fds_ptr = fds;
	} else {
		*fds_ptr = NULL;
	}
	return (0);
}

static inline abi_long
fbsd_copy_to_user_fdset(abi_ulong target_fds_addr, const fd_set *fds, int n)
{
	int i, nw, j, k;
	abi_long v;
	abi_ulong *target_fds;

	nw = (n + TARGET_ABI_BITS - 1) / TARGET_ABI_BITS;
	if (!(target_fds = lock_user(VERIFY_WRITE, target_fds_addr,
		    sizeof(abi_ulong) * nw, 0)))
		return (-TARGET_EFAULT);

	k = 0;
	for (i = 0; i < nw; i++) {
		v = 0;
		for (j = 0; j < TARGET_ABI_BITS; j++) {
			v |= ((FD_ISSET(k, fds) != 0) << j);
			k++;
		}
		__put_user(v, &target_fds[i]);
	}

	unlock_user(target_fds, target_fds_addr, sizeof(abi_ulong) * nw);

	return (0);
}

#if TARGET_ABI_BITS == 32
static inline uint64_t
target_offset64(uint32_t word0, uint32_t word1)
{
#ifdef TARGET_WORDS_BIGENDIAN
	return ((uint64_t)word0 << 32) | word1;
#else
	return ((uint64_t)word1 << 32) | word0;
#endif
}
#else /* TARGET_ABI_BITS != 32 */
static inline uint64_t
target_offset64(uint64_t word0, uint64_t word1)
{
	return (word0);
}
#endif /* TARGET_ABI_BITS != 32 */

/* ARM EABI and MIPS expect 64bit types aligned even on pairs of registers */
#ifdef TARGET_ARM
static inline int
regpairs_aligned(void *cpu_env) {

	return ((((CPUARMState *)cpu_env)->eabi) == 1);
}
#elif defined(TARGET_MIPS)
static inline int
regpairs_aligned(void *cpu_env) { return 1; }
#else
static inline int
regpairs_aligned(void *cpu_env) { return 0; }
#endif

static inline abi_long
unimplemented(int num)
{

	qemu_log("qemu: Unsupported syscall: %d\n", num);
	return (-TARGET_ENOSYS);
}

/* do_bind() must return target values and target errnos. */
static abi_long
do_bind(int sockfd, abi_ulong target_addr, socklen_t addrlen)
{
	abi_long ret;
	void *addr;

	if ((int)addrlen < 0)
		return (-TARGET_EINVAL);

	addr = alloca(addrlen + 1);
	ret = target_to_host_sockaddr(addr, target_addr, addrlen);
	if (ret)
		return (ret);

	return get_errno(bind(sockfd, addr, addrlen));
}

/* do_connect() must return target values and target errnos. */
static abi_long
do_connect(int sockfd, abi_ulong target_addr, socklen_t addrlen)
{
	abi_long ret;
	void *addr;

	if ((int)addrlen < 0)
		return (-TARGET_EINVAL);

	addr = alloca(addrlen);

	ret = target_to_host_sockaddr(addr, target_addr, addrlen);

	if (ret)
		return (ret);

	return (get_errno(connect(sockfd, addr, addrlen)));
}

/* do_sendrecvmsg() must return target values and target errnos. */
static abi_long
do_sendrecvmsg(int fd, abi_ulong target_msg, int flags, int send)
{
	abi_long ret, len;
	struct target_msghdr *msgp;
	struct msghdr msg;
	int count;
	struct iovec *vec;
	abi_ulong target_vec;

	if (!lock_user_struct(send ? VERIFY_READ : VERIFY_WRITE, msgp,
		target_msg, send ? 1 : 0))
		return (-TARGET_EFAULT);
	if (msgp->msg_name) {
		msg.msg_namelen = tswap32(msgp->msg_namelen);
		msg.msg_name = alloca(msg.msg_namelen);
		ret = target_to_host_sockaddr(msg.msg_name,
		    tswapal(msgp->msg_name), msg.msg_namelen);

		if (ret) {
			unlock_user_struct(msgp, target_msg, send ? 0 : 1);
			return (ret);
		}
	} else {
		msg.msg_name = NULL;
		msg.msg_namelen = 0;
	}
	msg.msg_controllen = 2 * tswapal(msgp->msg_controllen);
	msg.msg_control = alloca(msg.msg_controllen);
	msg.msg_flags = tswap32(msgp->msg_flags);

	count = tswapal(msgp->msg_iovlen);
	vec = alloca(count * sizeof(struct iovec));
	target_vec = tswapal(msgp->msg_iov);
	lock_iovec(send ? VERIFY_READ : VERIFY_WRITE, vec, target_vec, count,
	    send);
	msg.msg_iovlen = count;
	msg.msg_iov = vec;

	if (send) {
		ret = target_to_host_cmsg(&msg, msgp);
		if (0 == ret)
			ret = get_errno(sendmsg(fd, &msg, flags));
	} else {
		ret = get_errno(recvmsg(fd, &msg, flags));
		if (!is_error(ret)) {
			len = ret;
			ret = host_to_target_cmsg(msgp, &msg);
			if (!is_error(ret)) {
				msgp->msg_namelen = tswap32(msg.msg_namelen);
				if (msg.msg_name != NULL) {
					ret = host_to_target_sockaddr(
					    tswapal(msgp->msg_name),
					    msg.msg_name, msg.msg_namelen);
					if (ret)
						goto out;
				}
			}
			ret = len;
		}
	}
out:
	unlock_iovec(vec, target_vec, count, !send);
	unlock_user_struct(msgp, target_msg, send ? 0 : 1);
	return (ret);
}

/* do_accept() must return target values and target errnos. */
static abi_long
do_accept(int fd, abi_ulong target_addr, abi_ulong target_addrlen_addr)
{
	socklen_t addrlen;
	void *addr;
	abi_long ret;

	if (target_addr == 0)
		return get_errno(accept(fd, NULL, NULL));

	/* return EINVAL if addrlen pointer is invalid */
	if (get_user_u32(addrlen, target_addrlen_addr))
		return (-TARGET_EINVAL);

	if ((int)addrlen < 0)
		return (-TARGET_EINVAL);

	if (!access_ok(VERIFY_WRITE, target_addr, addrlen))
		return -TARGET_EINVAL;

	addr = alloca(addrlen);

	ret = get_errno(accept(fd, addr, &addrlen));
	if (!is_error(ret)) {
		host_to_target_sockaddr(target_addr, addr, addrlen);
		if (put_user_u32(addrlen, target_addrlen_addr))
			ret = (-TARGET_EFAULT);
	}
	return (ret);
}

/* do_getpeername() must return target values and target errnos. */
static abi_long
do_getpeername(int fd, abi_ulong target_addr, abi_ulong target_addrlen_addr)
{
	socklen_t addrlen;
	void *addr;
	abi_long ret;
	if (get_user_u32(addrlen, target_addrlen_addr))
		return (-TARGET_EFAULT);
	if ((int)addrlen < 0) {
		return (-TARGET_EINVAL);
	}
	if (!access_ok(VERIFY_WRITE, target_addr, addrlen))
		return (-TARGET_EFAULT);
	addr = alloca(addrlen);
	ret = get_errno(getpeername(fd, addr, &addrlen));
	if (!is_error(ret)) {
		host_to_target_sockaddr(target_addr, addr, addrlen);
		if (put_user_u32(addrlen, target_addrlen_addr))
			ret = (-TARGET_EFAULT);
	}
	return (ret);
}

/* do_getsockname() must return target values and target errnos. */
static abi_long
do_getsockname(int fd, abi_ulong target_addr, abi_ulong target_addrlen_addr)
{
	socklen_t addrlen;
	void *addr;
	abi_long ret;

	if (get_user_u32(addrlen, target_addrlen_addr))
		return (-TARGET_EFAULT);

	if ((int)addrlen < 0)
		return (-TARGET_EINVAL);

	if (!access_ok(VERIFY_WRITE, target_addr, addrlen))
		return (-TARGET_EFAULT);

	addr = alloca(addrlen);

	ret = get_errno(getsockname(fd, addr, &addrlen));
	if (!is_error(ret)) {
		host_to_target_sockaddr(target_addr, addr, addrlen);
		if (put_user_u32(addrlen, target_addrlen_addr))
			ret = (-TARGET_EFAULT);
	}
	return (ret);
}

/* do_socketpair() must return target values and target errnos. */
static abi_long
do_socketpair(int domain, int type, int protocol, abi_ulong target_tab_addr)
{
	int tab[2];
	abi_long ret;

	ret = get_errno(socketpair(domain, type, protocol, tab));
	if (!is_error(ret)) {
		if (put_user_s32(tab[0], target_tab_addr)
		    || put_user_s32(tab[1], target_tab_addr + sizeof(tab[0])))
			ret = (-TARGET_EFAULT);
	}
	return (ret);
}

/* do_sendto() must return target values and target errnos. */
static abi_long
do_sendto(int fd, abi_ulong msg, size_t len, int flags, abi_ulong target_addr,
    socklen_t addrlen)
{
	void *addr;
	void *host_msg;
	abi_long ret;

	if ((int)addrlen < 0)
		return (-TARGET_EINVAL);
	host_msg = lock_user(VERIFY_READ, msg, len, 1);
	if (!host_msg)
		return (-TARGET_EFAULT);
	if (target_addr) {
		addr = alloca(addrlen);
		ret = target_to_host_sockaddr(addr, target_addr, addrlen);
		if (ret) {
			unlock_user(host_msg, msg, 0);
			return (ret);
		}
		ret = get_errno(sendto(fd, host_msg, len, flags, addr,
			addrlen));
	} else {
		ret = get_errno(send(fd, host_msg, len, flags));
	}
	unlock_user(host_msg, msg, 0);
	return (ret);
}

/* do_recvfrom() must return target values and target errnos. */
static abi_long
do_recvfrom(int fd, abi_ulong msg, size_t len, int flags, abi_ulong target_addr,
    abi_ulong target_addrlen)
{
	socklen_t addrlen;
	void *addr;
	void *host_msg;
	abi_long ret;

	host_msg = lock_user(VERIFY_WRITE, msg, len, 0);
	if (!host_msg)
		return (-TARGET_EFAULT);
	if (target_addr) {
		if (get_user_u32(addrlen, target_addrlen)) {
			ret = -TARGET_EFAULT;
			goto fail;
		}
		if ((int)addrlen < 0) {
			ret = (-TARGET_EINVAL);
			goto fail;
		}
		addr = alloca(addrlen);
		ret = get_errno(recvfrom(fd, host_msg, len, flags, addr,
			&addrlen));
	} else {
		addr = NULL; /* To keep compiler quiet.  */
		ret = get_errno(qemu_recv(fd, host_msg, len, flags));
	}
	if (!is_error(ret)) {
		if (target_addr) {
			host_to_target_sockaddr(target_addr, addr, addrlen);
			if (put_user_u32(addrlen, target_addrlen)) {
				ret = -TARGET_EFAULT;
				goto fail;
			}
		}
		unlock_user(host_msg, msg, len);
	} else {
fail:
		unlock_user(host_msg, msg, 0);
	}
	return (ret);
}

/* do_freebsd_select() must return target values and target errnos. */
static abi_long
do_freebsd_select(int n, abi_ulong rfd_addr, abi_ulong wfd_addr,
    abi_ulong efd_addr, abi_ulong target_tv_addr)
{
	fd_set rfds, wfds, efds;
	fd_set *rfds_ptr, *wfds_ptr, *efds_ptr;
	struct timeval tv, *tv_ptr;
	abi_long ret;

	if ((ret = fbsd_copy_from_user_fdset_ptr(&rfds, &rfds_ptr, rfd_addr, n))
	    != 0)
		return (ret);
	if ((ret = fbsd_copy_from_user_fdset_ptr(&wfds, &wfds_ptr, wfd_addr, n))
	    != 0)
		return (ret);
	if ((ret = fbsd_copy_from_user_fdset_ptr(&efds, &efds_ptr, efd_addr, n))
	    != 0)
		return (ret);

	if (target_tv_addr) {
		if (fbsd_copy_from_user_timeval(&tv, target_tv_addr))
			return (-TARGET_EFAULT);
		tv_ptr = &tv;
	} else {
		tv_ptr = NULL;
	}

	ret = get_errno(select(n, rfds_ptr, wfds_ptr, efds_ptr, tv_ptr));

	if (!is_error(ret)) {
		if (rfd_addr && fbsd_copy_to_user_fdset(rfd_addr, &rfds, n))
			return (-TARGET_EFAULT);
		if (wfd_addr && fbsd_copy_to_user_fdset(wfd_addr, &wfds, n))
			return (-TARGET_EFAULT);
		if (efd_addr && fbsd_copy_to_user_fdset(efd_addr, &efds, n))
			return (-TARGET_EFAULT);

		if (target_tv_addr &&
		    fbsd_copy_to_user_timeval(&tv, target_tv_addr))
			return (-TARGET_EFAULT);
	}

	return (ret);
}

/* do_getsockopt() must return target values and target errnos. */
static abi_long
do_getsockopt(int sockfd, int level, int optname, abi_ulong optval_addr,
    abi_ulong optlen)
{
	abi_long ret;
	int len, val;
	socklen_t lv;

	switch(level) {
	case TARGET_SOL_SOCKET:
		level = SOL_SOCKET;
		switch (optname) {

		/* These don't just return a single integer */
		case TARGET_SO_LINGER:
		case TARGET_SO_RCVTIMEO:
		case TARGET_SO_SNDTIMEO:
		case TARGET_SO_ACCEPTFILTER:
			goto unimplemented;

		/* Options with 'int' argument.  */
		case TARGET_SO_DEBUG:
			optname = SO_DEBUG;
			goto int_case;

		case TARGET_SO_REUSEADDR:
			optname = SO_REUSEADDR;
			goto int_case;

		case TARGET_SO_REUSEPORT:
			optname = SO_REUSEPORT;
			goto int_case;

		case TARGET_SO_TYPE:
			optname = SO_TYPE;
			goto int_case;

		case TARGET_SO_ERROR:
			optname = SO_ERROR;
			goto int_case;

		case TARGET_SO_DONTROUTE:
			optname = SO_DONTROUTE;
			goto int_case;

		case TARGET_SO_BROADCAST:
			optname = SO_BROADCAST;
			goto int_case;

		case TARGET_SO_SNDBUF:
			optname = SO_SNDBUF;
			goto int_case;

		case TARGET_SO_RCVBUF:
			optname = SO_RCVBUF;
			goto int_case;

		case TARGET_SO_KEEPALIVE:
			optname = SO_KEEPALIVE;
			goto int_case;

		case TARGET_SO_OOBINLINE:
			optname = SO_OOBINLINE;
			goto int_case;

		case TARGET_SO_TIMESTAMP:
			optname = SO_TIMESTAMP;
			goto int_case;

		case TARGET_SO_RCVLOWAT:
			optname = SO_RCVLOWAT;
			goto int_case;

		case TARGET_SO_LISTENINCQLEN:
			optname = SO_LISTENINCQLEN;
			goto int_case;

		default:
int_case:
			if (get_user_u32(len, optlen))
				return (-TARGET_EFAULT);
			if (len < 0)
				return (-TARGET_EINVAL);
			lv = sizeof(lv);
			ret = get_errno(getsockopt(sockfd, level, optname,
				&val, &lv));
			if (ret < 0)
				return (ret);
			if (len > lv)
				len = lv;
			if (len == 4) {
				if (put_user_u32(val, optval_addr))
					return (-TARGET_EFAULT);
			} else {
				if (put_user_u8(val, optval_addr))
					return (-TARGET_EFAULT);
			}
			if (put_user_u32(len, optlen))
				return (-TARGET_EFAULT);
			break;

		}
		break;

	default:
unimplemented:
		gemu_log("getsockopt level=%d optname=%d not yet supported\n",
		    level, optname);
		ret = -TARGET_EOPNOTSUPP;
		break;
	}
	return (ret);
}

/* do_setsockopt() must return target values and target errnos. */
static abi_long
do_setsockopt(int sockfd, int level, int optname, abi_ulong optval_addr,
    socklen_t optlen)
{
	abi_long ret;

	switch(level) {
	case TARGET_SOL_SOCKET:
		switch (optname) {
		/* Options with 'int' argument.  */
		case TARGET_SO_DEBUG:
			optname = SO_DEBUG;
			break;

		case TARGET_SO_REUSEADDR:
			optname = SO_REUSEADDR;
			break;

		case TARGET_SO_REUSEPORT:
			optname = SO_REUSEADDR;
			break;

		case TARGET_SO_KEEPALIVE:
			optname = SO_KEEPALIVE;
			break;

		case TARGET_SO_DONTROUTE:
			optname = SO_DONTROUTE;
			break;

		case TARGET_SO_LINGER:
			optname = SO_LINGER;
			break;

		case TARGET_SO_BROADCAST:
			optname = SO_BROADCAST;
			break;

		case TARGET_SO_OOBINLINE:
			optname = SO_OOBINLINE;
			break;

		case TARGET_SO_SNDBUF:
			optname = SO_SNDBUF;
			break;

		case TARGET_SO_RCVBUF:
			optname = SO_RCVBUF;
			break;

		case TARGET_SO_SNDLOWAT:
			optname = SO_RCVLOWAT;
			break;

		case TARGET_SO_RCVLOWAT:
			optname = SO_RCVLOWAT;
			break;

		case TARGET_SO_SNDTIMEO:
			optname = SO_SNDTIMEO;
			break;

		case TARGET_SO_RCVTIMEO:
			optname = SO_RCVTIMEO;
			break;

		case TARGET_SO_ACCEPTFILTER:
			goto unimplemented;

		case TARGET_SO_NOSIGPIPE:
			optname = SO_NOSIGPIPE;
			break;

		case TARGET_SO_TIMESTAMP:
			optname = SO_TIMESTAMP;
			break;

		case TARGET_SO_BINTIME:
			optname = SO_BINTIME;
			break;

		case TARGET_SO_ERROR:
			optname = SO_ERROR;
			break;

		case TARGET_SO_SETFIB:
			optname = SO_ERROR;
			break;

		case TARGET_SO_USER_COOKIE:
			optname = SO_USER_COOKIE;
			break;

		default:
			goto unimplemented;
		}
		break;

	default:
unimplemented:
	gemu_log("Unsupported setsockopt level=%d optname=%d\n",
	    level, optname);
	ret = -TARGET_ENOPROTOOPT;
	}

	return (ret);
}

/* do_syscall() should always have a single exit point at the end so
   that actions, such as logging of syscall results, can be performed.
   All errnos that do_syscall() returns must be -TARGET_<errcode>. */
abi_long do_freebsd_syscall(void *cpu_env, int num, abi_long arg1,
                            abi_long arg2, abi_long arg3, abi_long arg4,
                            abi_long arg5, abi_long arg6, abi_long arg7,
                            abi_long arg8)
{
    abi_long ret;
    void *p;
    struct stat st;

#ifdef DEBUG
    gemu_log("freebsd syscall %d\n", num);
#endif
    if(do_strace)
        print_freebsd_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6);

    switch(num) {
    case TARGET_FREEBSD_NR_exit:
#ifdef TARGET_GPROF
        _mcleanup();
#endif
        gdb_exit(cpu_env, arg1);
        /* XXX: should free thread stack and CPU env */
        _exit(arg1);
        ret = 0; /* avoid warning */
        break;
    case TARGET_FREEBSD_NR_read:
        if (!(p = lock_user(VERIFY_WRITE, arg2, arg3, 0)))
            goto efault;
        ret = get_errno(read(arg1, p, arg3));
        unlock_user(p, arg2, ret);
        break;

    case TARGET_FREEBSD_NR_readv:
	{
		int count = arg3;
		struct iovec *vec;

		vec = alloca(count * sizeof(struct iovec));
		if (lock_iovec(VERIFY_WRITE, vec, arg2, count, 0) < 0)
			goto efault;
		ret = get_errno(readv(arg1, vec, count));
		unlock_iovec(vec, arg2, count, 1);
	}
	break;

    case TARGET_FREEBSD_NR_pread:
	if (!(p = lock_user(VERIFY_WRITE, arg2, arg3, 0)))
		goto efault;
	ret = get_errno(pread(arg1, p, arg3, target_offset64(arg4, arg5)));
	unlock_user(p, arg2, ret);
	break;

    case TARGET_FREEBSD_NR_preadv:
	{
		int count = arg3;
		struct iovec *vec;

		vec = alloca(count * sizeof(struct iovec));
		if (lock_iovec(VERIFY_WRITE, vec, arg2, count, 0) < 0)
			goto efault;
		ret = get_errno(preadv(arg1, vec, count,
			target_offset64(arg4, arg5)));
		unlock_iovec(vec, arg2, count, 1);
	}
	break;

    case TARGET_FREEBSD_NR_write:
        if (!(p = lock_user(VERIFY_READ, arg2, arg3, 1)))
            goto efault;
        ret = get_errno(write(arg1, p, arg3));
        unlock_user(p, arg2, 0);
        break;

    case TARGET_FREEBSD_NR_writev:
        {
            int count = arg3;
            struct iovec *vec;

            vec = alloca(count * sizeof(struct iovec));
            if (lock_iovec(VERIFY_READ, vec, arg2, count, 1) < 0)
                goto efault;
            ret = get_errno(writev(arg1, vec, count));
            unlock_iovec(vec, arg2, count, 0);
        }
        break;

    case TARGET_FREEBSD_NR_pwrite:
	if (!(p = lock_user(VERIFY_READ, arg2, arg3, 1)))
		goto efault;
	ret = get_errno(pwrite(arg1, p, arg3, target_offset64(arg4, arg5)));
	unlock_user(p, arg2, 0); 
	break;

    case TARGET_FREEBSD_NR_pwritev:
	{
		int count = arg3;
		struct iovec *vec;

		vec = alloca(count * sizeof(struct iovec));
		if (lock_iovec(VERIFY_READ, vec, arg2, count, 1) < 0)
			goto efault;
		ret = get_errno(pwritev(arg1, vec, count,
			target_offset64(arg4, arg5)));
		unlock_iovec(vec, arg2, count, 0);
	}
	break;

    case TARGET_FREEBSD_NR_open:
        if (!(p = lock_user_string(arg1)))
            goto efault;
        ret = get_errno(open(path(p),
                             target_to_host_bitmask(arg2, fcntl_flags_tbl),
                             arg3));
        unlock_user(p, arg1, 0);
        break;

    case TARGET_FREEBSD_NR_mmap:
        ret = get_errno(target_mmap(arg1, arg2, arg3,
                                    target_to_host_bitmask(arg4, mmap_flags_tbl),
                                    arg5,
                                    arg6));
        break;

    case TARGET_FREEBSD_NR_munmap:
        ret = get_errno(target_munmap(arg1, arg2));
        break;

    case TARGET_FREEBSD_NR_mprotect:
        ret = get_errno(target_mprotect(arg1, arg2, arg3));
        break;

    case TARGET_FREEBSD_NR_msync:
	ret = get_errno(msync(g2h(arg1), arg2, arg3));
	break;

    case TARGET_FREEBSD_NR_mlock:
	ret = get_errno(mlock(g2h(arg1), arg2));
	break;

    case TARGET_FREEBSD_NR_munlock:
	ret = get_errno(munlock(g2h(arg1), arg2));
	break;

    case TARGET_FREEBSD_NR_mlockall:
	ret = get_errno(mlockall(arg1));
	break;

    case TARGET_FREEBSD_NR_munlockall:
	ret = get_errno(munlockall());
	break;

    case TARGET_FREEBSD_NR_madvise:
	/*
	 * A straight passthrough may not be safe because qemu sometimes
	 * turns private file-backed mapping into anonymous mappings. This
	 * will break MADV_DONTNEED.  This is a hint, so ignoring and returing
	 * success is ok.
	 */
	ret = get_errno(0);
	break;

    case TARGET_FREEBSD_NR_break:
        ret = do_obreak(arg1);
        break;
#ifdef __FreeBSD__
    case TARGET_FREEBSD_NR___sysctl:
        ret = do_freebsd_sysctl(arg1, arg2, arg3, arg4, arg5, arg6);
        break;
#endif
    case TARGET_FREEBSD_NR_sysarch:
        ret = do_freebsd_sysarch(cpu_env, arg1, arg2);
        break;
    case TARGET_FREEBSD_NR_syscall:
    case TARGET_FREEBSD_NR___syscall:
        ret = do_freebsd_syscall(cpu_env,arg1 & 0xffff,arg2,arg3,arg4,arg5,arg6,arg7,arg8,0);
        break;

    case TARGET_FREEBSD_NR_stat:
	 if (!(p = lock_user_string(arg1)))
            goto efault;
        ret = get_errno(stat(path(p), &st));
        unlock_user(p, arg1, 0);
        goto do_stat;

    case TARGET_FREEBSD_NR_lstat:
        if (!(p = lock_user_string(arg1)))
            goto efault;
        ret = get_errno(lstat(path(p), &st));
        unlock_user(p, arg1, 0);
        goto do_stat;

    case TARGET_FREEBSD_NR_fstat:
        {
            ret = get_errno(fstat(arg1, &st));

do_stat:
	if (!is_error(ret)) {
		struct target_freebsd_stat *target_st;
		
		if (!lock_user_struct(VERIFY_WRITE, target_st, arg2, 0))
                    goto efault;
                memset(target_st, 0, sizeof(*target_st));
                __put_user(st.st_dev, &target_st->st_dev);
                __put_user(st.st_ino, &target_st->st_ino);
                __put_user(st.st_mode, &target_st->st_mode);
                __put_user(st.st_nlink, &target_st->st_nlink);
                __put_user(st.st_uid, &target_st->st_uid);
                __put_user(st.st_gid, &target_st->st_gid);
                __put_user(st.st_rdev, &target_st->st_rdev);
                __put_user(st.st_atim.tv_sec, &target_st->st_atim.tv_sec);
		__put_user(st.st_atim.tv_nsec, &target_st->st_atim.tv_nsec);
                __put_user(st.st_mtim.tv_sec, &target_st->st_mtim.tv_sec);
		__put_user(st.st_mtim.tv_nsec, &target_st->st_mtim.tv_nsec);
                __put_user(st.st_ctim.tv_sec, &target_st->st_ctim.tv_sec);
		__put_user(st.st_ctim.tv_nsec, &target_st->st_ctim.tv_nsec);
                __put_user(st.st_size, &target_st->st_size);
                __put_user(st.st_blocks, &target_st->st_blocks);
                __put_user(st.st_blksize, &target_st->st_blksize);
		__put_user(st.st_flags, &target_st->st_flags);
		__put_user(st.st_gen, &target_st->st_gen);
		/* st_lspare not used */
		__put_user(st.st_birthtim.tv_sec,
		    &target_st->st_birthtim.tv_sec);
		__put_user(st.st_birthtim.tv_nsec,
		    &target_st->st_birthtim.tv_nsec);
                unlock_user_struct(target_st, arg2, 1);
	  }

	}
        break;

    case TARGET_FREEBSD_NR_nanosleep:
	 {
		 struct timespec req, rem;

		 target_to_host_timespec(&req, arg1);
		 ret = get_errno(nanosleep(&req, &rem));
		 if (is_error(ret) && arg2)
			 host_to_target_timespec(arg2, &rem);
	 }
	 break;

    case TARGET_FREEBSD_NR_clock_gettime:
	{
		struct timespec ts;

		ret = get_errno(clock_gettime(arg1, &ts));
		if (!is_error(ret)) {
			if (host_to_target_timespec(arg2, &ts))
				goto efault;
		}
    	}
        break;

   case TARGET_FREEBSD_NR_clock_getres:
	{
		struct timespec ts;

		ret = get_errno(clock_getres(arg1, &ts));
		if (!is_error(ret)) {
			if (host_to_target_timespec(arg2, &ts))
				goto efault;
		}
	}
	break;

    case TARGET_FREEBSD_NR_clock_settime:
	{
		struct timespec ts;

		if (target_to_host_timespec(&ts, arg2) != 0)
			goto efault;
		ret = get_errno(clock_settime(arg1, &ts));
	}
        break;

     case TARGET_FREEBSD_NR_gettimeofday:
	{
		struct timeval tv;
		struct timezone tz, *target_tz;
		if (arg2 != 0) {
			if (!lock_user_struct(VERIFY_READ, target_tz, arg2, 0))
				goto efault;
			__get_user(tz.tz_minuteswest,
			    &target_tz->tz_minuteswest);
			__get_user(tz.tz_dsttime, &target_tz->tz_dsttime);
			unlock_user_struct(target_tz, arg2, 1);
		}
		ret = get_errno(gettimeofday(&tv, arg2 != 0 ? &tz : NULL));
		if (!is_error(ret)) {
			if (fbsd_copy_to_user_timeval(&tv, arg1))
				goto efault;
		}
	}
	break;

    case TARGET_FREEBSD_NR_settimeofday:
	{
		struct timeval tv;
		struct timezone tz, *target_tz;

		if (arg2 != 0) {
			if (!lock_user_struct(VERIFY_READ, target_tz, arg2, 0))
				goto efault;
			__get_user(tz.tz_minuteswest,
			    &target_tz->tz_minuteswest);
			__get_user(tz.tz_dsttime, &target_tz->tz_dsttime);
			unlock_user_struct(target_tz, arg2, 1);
		}
		if (fbsd_copy_from_user_timeval(&tv, arg1))
			goto efault;
		ret = get_errno(settimeofday(&tv, arg2 != 0 ? & tz : NULL));
	}
        break;

#ifdef __FreeBSD__
    case TARGET_FREEBSD_NR_kevent:
        {
           struct kevent *changelist = NULL, *eventlist = NULL;
           struct target_kevent *target_changelist, *target_eventlist;
           struct timespec ts;
           int i;
           
           if (arg3 != 0) {
              if (!(target_changelist = lock_user(VERIFY_READ, arg2,
                  sizeof(struct target_kevent) * arg3, 1)))
                     goto efault;
              changelist = alloca(sizeof(struct kevent) * arg3);

              for (i = 0; i < arg3; i++) {
                 __get_user(changelist[i].ident, &target_changelist[i].ident);
                 __get_user(changelist[i].filter, &target_changelist[i].filter);
                 __get_user(changelist[i].flags, &target_changelist[i].flags);
                 __get_user(changelist[i].fflags, &target_changelist[i].fflags);
                 __get_user(changelist[i].data, &target_changelist[i].data);
		/* XXX: This is broken when running a 64bits target on a 32bits host */
                 /* __get_user(changelist[i].udata, &target_changelist[i].udata); */
#if TARGET_ABI_BITS == 32
		 changelist[i].udata = (void *)(uintptr_t)target_changelist[i].udata;
		 tswap32s((uint32_t *)&changelist[i].udata);
#else
		 changelist[i].udata = (void *)(uintptr_t)target_changelist[i].udata;
		 tswap64s((uint64_t *)&changelist[i].udata);
#endif
               }
               unlock_user(target_changelist, arg2, 0);
           }

           if (arg5 != 0)
              eventlist = alloca(sizeof(struct kevent) * arg5);
           if (arg6 != 0)
              if (target_to_host_timespec(&ts, arg6))
                goto efault;
           ret = get_errno(kevent(arg1, changelist, arg3, eventlist, arg5,
              arg6 != 0 ? &ts : NULL));
           if (!is_error(ret)) {
               if (!(target_eventlist = lock_user(VERIFY_WRITE, arg4, 
                   sizeof(struct target_kevent) * arg5, 0)))
                      goto efault;
               for (i = 0; i < arg5; i++) {
                 __put_user(eventlist[i].ident, &target_eventlist[i].ident);
                 __put_user(eventlist[i].filter, &target_eventlist[i].filter);
                 __put_user(eventlist[i].flags, &target_eventlist[i].flags);
                 __put_user(eventlist[i].fflags, &target_eventlist[i].fflags);
                 __put_user(eventlist[i].data, &target_eventlist[i].data);
               /* __put_user(eventlist[i].udata, &target_eventlist[i].udata); */
#if TARGET_ABI_BITS == 32
		 tswap32s((uint32_t *)&eventlist[i].data);
		 target_eventlist[i].data = (uintptr_t)eventlist[i].data;
#else
		 tswap64s((uint64_t *)&eventlist[i].data);
		 target_eventlist[i].data = (uintptr_t)eventlist[i].data;
#endif
               }
               unlock_user(target_eventlist, arg4, sizeof(struct target_kevent) * arg5);

              
           }
        }
	break;
#endif

    case TARGET_FREEBSD_NR_execve:
        {
            char **argp, **envp;
            int argc, envc;
            abi_ulong gp;
            abi_ulong guest_argp;
            abi_ulong guest_envp;
            abi_ulong addr;
            char **q;
            int total_size = 0;

            argc = 0;
            guest_argp = arg2;
            for (gp = guest_argp; gp; gp += sizeof(abi_ulong)) {
                if (get_user_ual(addr, gp))
                    goto efault;
                if (!addr)
                    break;
                argc++;
            }
            envc = 0;
            guest_envp = arg3;
            for (gp = guest_envp; gp; gp += sizeof(abi_ulong)) {
                if (get_user_ual(addr, gp))
                    goto efault;
                if (!addr)
                    break;
                envc++;
            }

            argp = alloca((argc + 1) * sizeof(void *));
            envp = alloca((envc + 1) * sizeof(void *));

            for (gp = guest_argp, q = argp; gp;
                  gp += sizeof(abi_ulong), q++) {
                if (get_user_ual(addr, gp))
                    goto execve_efault;
                if (!addr)
                    break;
                if (!(*q = lock_user_string(addr)))
                    goto execve_efault;
                total_size += strlen(*q) + 1;
            }
            *q = NULL;

            for (gp = guest_envp, q = envp; gp;
                  gp += sizeof(abi_ulong), q++) {
                if (get_user_ual(addr, gp))
                    goto execve_efault;
                if (!addr)
                    break;
                if (!(*q = lock_user_string(addr)))
                    goto execve_efault;
                total_size += strlen(*q) + 1;
            }
            *q = NULL;

            /* This case will not be caught by the host's execve() if its
               page size is bigger than the target's. */
            if (total_size > MAX_ARG_PAGES * TARGET_PAGE_SIZE) {
                ret = -TARGET_E2BIG;
                goto execve_end;
            }
            if (!(p = lock_user_string(arg1)))
                goto execve_efault;
            ret = get_errno(execve(p, argp, envp));
            unlock_user(p, arg1, 0);

            goto execve_end;

        execve_efault:
            ret = -TARGET_EFAULT;

        execve_end:
            for (gp = guest_argp, q = argp; *q;
                  gp += sizeof(abi_ulong), q++) {
                if (get_user_ual(addr, gp)
                    || !addr)
                    break;
                unlock_user(*q, addr, 0);
            }
            for (gp = guest_envp, q = envp; *q;
                  gp += sizeof(abi_ulong), q++) {
                if (get_user_ual(addr, gp)
                    || !addr)
                    break;
                unlock_user(*q, addr, 0);
            }
        }
        break;

    case TARGET_FREEBSD_NR_pipe:
	{
		int host_pipe[2];
		int host_ret = pipe(host_pipe);

		if (!is_error(host_ret)) {
#if defined(TARGET_ALPHA)
			((CPUAlphaState *)cpu_env)->ir[IR_A4] =
			    host_pipe[1];
#elif defined(TARGET_ARM)
			((CPUARMState *)cpu_env)->regs[1] =
			    host_pipe[1];
#elif defined(TARGET_MIPS)
			((CPUMIPSState*)cpu_env)->active_tc.gpr[3] =
			    host_pipe[1];
#elif defined(TARGET_SH4)
			((CPUSH4State*)cpu_env)->gregs[1] =
			    host_pipe[1];
#else
#warning Architecture not supported for pipe(2).
#endif
			ret = host_pipe[0];
		} else
			ret = get_errno(host_ret);
	}
	break;

    case TARGET_FREEBSD_NR_lseek:
	{
#if defined(TARGET_MIPS) && TARGET_ABI_BITS == 32
		/* 32-bit MIPS uses two 32 registers for 64 bit arguments */
		int64_t res = lseek(arg1, target_offset64(arg2, arg3), arg4);

		if (res == -1) {
			ret = get_errno(res);
		} else {
			ret = res & 0xFFFFFFFF;
			((CPUMIPSState*)cpu_env)->active_tc.gpr[3] =
			    (res >> 32) & 0xFFFFFFFF;
		}
#else
		ret = get_errno(lseek(arg1, arg2, arg3));
#endif
	}
	break;

    case TARGET_FREEBSD_NR_select:
	ret = do_freebsd_select(arg1, arg2, arg3, arg4, arg5);
	break;

    case TARGET_FREEBSD_NR_setrlimit:
	{
		int resource = target_to_host_resource(arg1);
		struct target_rlimit *target_rlim;
		struct rlimit rlim;

		if (!lock_user_struct(VERIFY_READ, target_rlim, arg2, 1))
			goto efault;
		rlim.rlim_cur = target_to_host_rlim(target_rlim->rlim_cur);
		rlim.rlim_max = target_to_host_rlim(target_rlim->rlim_max);
		unlock_user_struct(target_rlim, arg2, 0);
		ret = get_errno(setrlimit(resource, &rlim));
	}
	break;


    case TARGET_FREEBSD_NR_getrlimit:
	{
		int resource = target_to_host_resource(arg1);
		struct target_rlimit *target_rlim;
		struct rlimit rlim;

		ret = get_errno(getrlimit(resource, &rlim));
		if (!is_error(ret)) {
			if (!lock_user_struct(VERIFY_WRITE, target_rlim, arg2,
				0))
				goto efault;
			target_rlim->rlim_cur =
			    host_to_target_rlim(rlim.rlim_cur);
			target_rlim->rlim_max =
			    host_to_target_rlim(rlim.rlim_max);
			unlock_user_struct(target_rlim, arg2, 1);
		}
	}
	break;

    case TARGET_FREEBSD_NR_setitimer:
	{
		struct itimerval value, ovalue, *pvalue;

		if (arg2) {
			pvalue = &value;
			if (fbsd_copy_from_user_timeval(&pvalue->it_interval,
				arg2) || fbsd_copy_from_user_timeval(
				&pvalue->it_value, arg2 +
				sizeof(struct target_timeval)))
				goto efault;
		} else {
			pvalue = NULL;
		}
		ret = get_errno(setitimer(arg1, pvalue, &ovalue));
		if (!is_error(ret) && arg3) {
			if (fbsd_copy_to_user_timeval(&ovalue.it_interval, arg3)
			    || fbsd_copy_to_user_timeval(&ovalue.it_value,
				arg3 + sizeof(struct target_timeval)))
				goto efault;
		}
	}
	break;

    case TARGET_FREEBSD_NR_getitimer:
	{
		struct itimerval value;

		ret = get_errno(getitimer(arg1, &value));
		if (!is_error(ret) && arg2) {
			if (fbsd_copy_to_user_timeval(&value.it_interval, arg2)
			    || fbsd_copy_to_user_timeval(&value.it_value,
				arg2 + sizeof(struct target_timeval)))
				goto efault;
		}
	}
	break;

    case TARGET_FREEBSD_NR_utimes:
	{
		struct timeval *tvp, tv[2];

		if (arg2) {
			if (fbsd_copy_from_user_timeval(&tv[0], arg2)
			    || fbsd_copy_from_user_timeval(&tv[1],
				arg2 + sizeof(struct target_timeval)))

				goto efault;
			tvp = tv;
		} else {
			tvp = NULL;
		}
		if (!(p = lock_user_string(arg1)))
			goto efault;
		ret = get_errno(utimes(p, tvp));
		unlock_user(p, arg1, 0);
	}
	break;

    case TARGET_FREEBSD_NR_lutimes:
	{
		struct timeval *tvp, tv[2];

		if (arg2) {
			if (fbsd_copy_from_user_timeval(&tv[0], arg2)
			    || fbsd_copy_from_user_timeval(&tv[1],
				arg2 + sizeof(struct target_timeval)))

				goto efault;
			tvp = tv;
		} else {
			tvp = NULL;
		}
		if (!(p = lock_user_string(arg1)))
			goto efault;
		ret = get_errno(lutimes(p, tvp));
		unlock_user(p, arg1, 0);
	}
	break;

    case TARGET_FREEBSD_NR_futimes:
	{
		struct timeval *tvp, tv[2];

		if (arg2) {
			if (fbsd_copy_from_user_timeval(&tv[0], arg2)
			    || fbsd_copy_from_user_timeval(&tv[1],
				arg2 + sizeof(struct target_timeval)))
				goto efault;
			tvp = tv;
		} else {
			tvp = NULL;
		}
		ret = get_errno(futimes(arg1, tvp));
	}
	break;

    case TARGET_FREEBSD_NR_futimesat:
	{
		struct timeval *tvp, tv[2];

		if (arg3) {
			if (fbsd_copy_from_user_timeval(&tv[0], arg3)
			    || fbsd_copy_from_user_timeval(&tv[1],
				arg3 + sizeof(struct target_timeval)))
				goto efault;
			tvp = tv;
		} else {
			tvp = NULL;
		}
		if (!(p = lock_user_string(arg2)))
			goto efault;
		ret = get_errno(futimesat(arg1, path(p), tvp));
		unlock_user(p, arg2, 0);
	}
	break;

    case TARGET_FREEBSD_NR_access:
	if (!(p = lock_user_string(arg1)))
		goto efault;
	ret = get_errno(access(path(p), arg2));
	unlock_user(p, arg1, 0);

    case TARGET_FREEBSD_NR_eaccess:
	if (!(p = lock_user_string(arg1)))
		goto efault;
	ret = get_errno(eaccess(path(p), arg2));
	unlock_user(p, arg1, 0);
	break;

    case TARGET_FREEBSD_NR_faccessat:
	if (!(p = lock_user_string(arg2)))
		goto efault;
	ret = get_errno(faccessat(arg1, p, arg3, arg4));
	unlock_user(p, arg2, 0);
	break;

    case TARGET_FREEBSD_NR_chdir:
	if (!(p = lock_user_string(arg1)))
		goto efault;
	ret = get_errno(chdir(p));
	unlock_user(p, arg1, 0);
	break;

    case TARGET_FREEBSD_NR_fchdir:
	ret = get_errno(fchdir(arg1));
	break;

    case TARGET_FREEBSD_NR_rename:
	{
		void *p2;

		p = lock_user_string(arg1);
		p2 = lock_user_string(arg2);
		if (!p || !p2)
			ret = -TARGET_EFAULT;
		else
			ret = get_errno(rename(p, p2));
		unlock_user(p2, arg2, 0);
		unlock_user(p, arg1, 0);
	}
	break;

    case TARGET_FREEBSD_NR_renameat:
	{
		void *p2;

		p  = lock_user_string(arg2);
		p2 = lock_user_string(arg4);
		if (!p || !p2)
			ret = -TARGET_EFAULT;
		else
			ret = get_errno(renameat(arg1, p, arg3, p2));
		unlock_user(p2, arg4, 0);
		unlock_user(p, arg2, 0);
	}
	break;

    case TARGET_FREEBSD_NR_link:
	{
		void * p2;

		p = lock_user_string(arg1);
		p2 = lock_user_string(arg2);
		if (!p || !p2)
			ret = -TARGET_EFAULT;
		else
			ret = get_errno(link(p, p2));
		unlock_user(p2, arg2, 0);
		unlock_user(p, arg1, 0);
	}
	break;

    case TARGET_FREEBSD_NR_linkat:
	{
		void * p2 = NULL;

		if (!arg2 || !arg4)
			goto efault;

		p  = lock_user_string(arg2);
		p2 = lock_user_string(arg4);
		if (!p || !p2)
			ret = -TARGET_EFAULT;
		else
			ret = get_errno(linkat(arg1, p, arg3, p2, arg5));
		unlock_user(p, arg2, 0);
		unlock_user(p2, arg4, 0);
	}
	break;

    case TARGET_FREEBSD_NR_unlink:
	if (!(p = lock_user_string(arg1)))
		goto efault;
	ret = get_errno(unlink(p));
	unlock_user(p, arg1, 0);
	break;

    case TARGET_FREEBSD_NR_unlinkat:
	if (!(p = lock_user_string(arg2)))
		goto efault;
	ret = get_errno(unlinkat(arg1, p, arg3));
	unlock_user(p, arg2, 0);
	break;

    case TARGET_FREEBSD_NR_mkdir:
	if (!(p = lock_user_string(arg1)))
		goto efault;
	ret = get_errno(mkdir(p, arg2));
	unlock_user(p, arg1, 0);
	break;

    case TARGET_FREEBSD_NR_mkdirat:
	 if (!(p = lock_user_string(arg2)))
		 goto efault;
	 ret = get_errno(mkdirat(arg1, p, arg3));
	 unlock_user(p, arg2, 0);
	 break;

    case TARGET_FREEBSD_NR_rmdir:
	 if (!(p = lock_user_string(arg1)))
		 goto efault;
	 ret = get_errno(rmdir(p));
	 unlock_user(p, arg1, 0);
	 break;

    case TARGET_FREEBSD_NR___getcwd:
	 if (!(p = lock_user(VERIFY_WRITE, arg1, arg2, 0)))
		 goto efault;
	 ret = get_errno(__getcwd(p, arg2));
	 unlock_user(p, arg1, ret);
	 break;

    case TARGET_FREEBSD_NR_dup:
	 ret = get_errno(dup(arg1));
	 break;

    case TARGET_FREEBSD_NR_dup2:
	 ret = get_errno(dup2(arg1, arg2));
	 break;

    case TARGET_FREEBSD_NR_truncate:
	 if (!(p = lock_user_string(arg1)))
		 goto efault;
	 if (regpairs_aligned(cpu_env)) {
		 arg2 = arg3;
		 arg3 = arg4;
	 }
	 ret = truncate(p, target_offset64(arg2, arg3));
	 unlock_user(p, arg1, 0);
	 break;

    case TARGET_FREEBSD_NR_ftruncate:
	 if (regpairs_aligned(cpu_env)) {
		 arg2 = arg3;
		 arg3 = arg4;
	 }
	 ret = ftruncate(arg1, target_offset64(arg2, arg3));
	 break;

    case TARGET_FREEBSD_NR_acct:
	 if (arg1 == 0) {
		 ret = get_errno(acct(NULL));
	 } else {
		 if (!(p = lock_user_string(arg1)))
			 goto efault;
		 ret = get_errno(acct(path(p)));
		 unlock_user(p, arg1, 0);
	 }
	 break;

    case TARGET_FREEBSD_NR_sync:
	 sync();
	 ret = 0;
	 break;

    case TARGET_FREEBSD_NR_mount:
	 {
		 void *p2;

		 /* We need to look at the data field. */
		 p = lock_user_string(arg1);	/* type */
		 p2 = lock_user_string(arg2);	/* dir */
		 if (!p || !p2)
			 ret = -TARGET_EFAULT;
		 else {
			 /*
			  * XXX arg5 should be locked, but it isn't clear
			  * how to do that since it's it may be not be a
			  * NULL-terminated string.
			  */
			 if ( ! arg5 )
				 ret = get_errno(mount(p, p2, arg3, NULL));
			 else
				 ret = get_errno(mount(p, p2, arg3, g2h(arg5)));
		 }
		 unlock_user(p, arg1, 0);
		 unlock_user(p2, arg1, 0);
	 }
	 break;

    case TARGET_FREEBSD_NR_unmount:
	 if (!(p = lock_user_string(arg1)))
		 goto efault;
	 ret = get_errno(unmount(p, arg2));
	 unlock_user(p, arg1, 0);
	 break;

    case TARGET_FREEBSD_NR_nmount:
	 {
		 int count = arg2;
		 struct iovec *vec;

		 vec = alloca(count * sizeof(struct iovec));
		 if (lock_iovec(VERIFY_READ, vec, arg2, count, 1) < 0)
			 goto efault;
		 ret = get_errno(nmount(vec, count, arg3));
		 unlock_iovec(vec, arg2, count, 0);
	 }
	 break;

    case TARGET_FREEBSD_NR_symlink:
	 {
		 void *p2;

		 p = lock_user_string(arg1);
		 p2 = lock_user_string(arg2);
		 if (!p || !p2)
			 ret = -TARGET_EFAULT;
		 else
			 ret = get_errno(symlink(p, p2));
		 unlock_user(p2, arg2, 0);
		 unlock_user(p, arg1, 0);
	 }
	 break;

    case TARGET_FREEBSD_NR_symlinkat:
	 {
		 void *p2;

		 p  = lock_user_string(arg1);
		 p2 = lock_user_string(arg3);
		 if (!p || !p2)
			 ret = -TARGET_EFAULT;
		 else
			 ret = get_errno(symlinkat(p, arg2, p2));
		 unlock_user(p2, arg3, 0);
		 unlock_user(p, arg1, 0);
	 }
	 break;

    case TARGET_FREEBSD_NR_readlink:
	 {
		 void *p2;

		 p = lock_user_string(arg1);
		 p2 = lock_user(VERIFY_WRITE, arg2, arg3, 0);
		 if (!p || !p2)
			 ret = -TARGET_EFAULT;
		 else
			 ret = get_errno(readlink(path(p), p2, arg3));
		 unlock_user(p2, arg2, ret);
		 unlock_user(p, arg1, 0);
	 }
	 break;

    case TARGET_FREEBSD_NR_readlinkat:
	 {
		 void *p2;
		 p = lock_user_string(arg2);
		 p2 = lock_user(VERIFY_WRITE, arg3, arg4, 0);

		 if (!p || !p2)
			 ret = -TARGET_EFAULT;
		 else
			 ret = get_errno(readlinkat(arg1, path(p), p2, arg4));
		 unlock_user(p2, arg3, ret);
		 unlock_user(p, arg2, 0);
	 }
	 break;

    case TARGET_FREEBSD_NR_chmod:
	 if (!(p = lock_user_string(arg1)))
		 goto efault;
	 ret = get_errno(chmod(p, arg2));
	 unlock_user(p, arg1, 0);
	 break;

    case TARGET_FREEBSD_NR_fchmod:
	 ret = get_errno(fchmod(arg1, arg2));
	 break;

    case TARGET_FREEBSD_NR_lchmod:
	 if (!(p = lock_user_string(arg1)))
		 goto efault;
	 ret = get_errno(lchmod(p, arg2));
	 unlock_user(p, arg1, 0);
	 break;

    case TARGET_FREEBSD_NR_fchmodat:
	 if (!(p = lock_user_string(arg2)))
		 goto efault;
	 ret = get_errno(fchmodat(arg1, p, arg3, arg4));
	 unlock_user(p, arg2, 0);
	 break;

    case TARGET_FREEBSD_NR_mknod:
	 if (!(p = lock_user_string(arg1)))
		 goto efault;
	 ret = get_errno(mknod(p, arg2, arg3));
	 unlock_user(p, arg1, 0);
	 break;

    case TARGET_FREEBSD_NR_mknodat:
	 if (!(p = lock_user_string(arg2)))
		 goto efault;
	 ret = get_errno(mknodat(arg1, p, arg3, arg4));
	 unlock_user(p, arg2, 0);
	 break;

    case TARGET_FREEBSD_NR_chown:
	 if (!(p = lock_user_string(arg1)))
		 goto efault;
	 ret = get_errno(chown(p, arg2, arg3));
	 unlock_user(p, arg1, 0);
	 break;

    case TARGET_FREEBSD_NR_fchown:
	 ret = get_errno(fchown(arg1, arg2, arg3));
	 break;

    case TARGET_FREEBSD_NR_lchown:
	 if (!(p = lock_user_string(arg1)))
		 goto efault;
	 ret = get_errno(lchown(p, arg2, arg3));
	 unlock_user(p, arg1, 0);
	 break;

    case TARGET_FREEBSD_NR_fchownat:
	 if (!(p = lock_user_string(arg2)))
		 goto efault;
	 ret = get_errno(fchownat(arg1, p, arg3, arg4, arg5));
	 unlock_user(p, arg2, 0);
	 break;

    case TARGET_FREEBSD_NR_umask:
	 ret = get_errno(umask(arg1));
	 break;

    case TARGET_FREEBSD_NR_fcntl:
	 {
		 int host_cmd;
		 struct flock fl;
		 struct target_flock *target_fl;

		 host_cmd = target_to_host_fcntl_cmd(arg2);
		 if (-TARGET_EINVAL == host_cmd) {
			 ret = host_cmd;
			 break;
		 }

		 switch(arg2) {
		 case TARGET_F_GETLK:
			 if (!lock_user_struct(VERIFY_READ, target_fl, arg3, 1))
				 return (-TARGET_EFAULT);
			 fl.l_type = tswap16(target_fl->l_type);
			 fl.l_whence = tswap16(target_fl->l_whence);
			 fl.l_start = tswapal(target_fl->l_start);
			 fl.l_len = tswapal(target_fl->l_len);
			 fl.l_pid = tswap32(target_fl->l_pid);
			 fl.l_sysid = tswap32(target_fl->l_sysid);
			 unlock_user_struct(target_fl, arg3, 0);
			 ret = get_errno(fcntl(arg1, host_cmd, &fl));
			 if (0 == ret) {
				 if (!lock_user_struct(VERIFY_WRITE, target_fl,
					 arg3, 0))
					 return (-TARGET_EFAULT);
				 target_fl->l_type = tswap16(fl.l_type);
				 target_fl->l_whence = tswap16(fl.l_whence);
				 target_fl->l_start = tswapal(fl.l_start);
				 target_fl->l_len = tswapal(fl.l_len);
				 target_fl->l_pid = tswap32(fl.l_pid);
				 target_fl->l_sysid = tswap32(fl.l_sysid);
				 unlock_user_struct(target_fl, arg3, 1);
			 }
			 break;

		 case TARGET_F_SETLK:
		 case TARGET_F_SETLKW:
			 if (!lock_user_struct(VERIFY_READ, target_fl, arg3, 1))
				 return (-TARGET_EFAULT);
			 fl.l_type = tswap16(target_fl->l_type);
			 fl.l_whence = tswap16(target_fl->l_whence);
			 fl.l_start = tswapal(target_fl->l_start);
			 fl.l_len = tswapal(target_fl->l_len);
			 fl.l_pid = tswap32(target_fl->l_pid);
			 fl.l_sysid = tswap32(target_fl->l_sysid);
			 unlock_user_struct(target_fl, arg3, 0);
			 ret = get_errno(fcntl(arg1, host_cmd, &fl));
			 break;

		 case TARGET_F_DUPFD:
		 case TARGET_F_DUP2FD:
		 case TARGET_F_GETOWN:
		 case TARGET_F_SETOWN:
		 case TARGET_F_GETFD:
		 case TARGET_F_SETFD:
		 case TARGET_F_GETFL:
		 case TARGET_F_SETFL:
		 case TARGET_F_READAHEAD:
		 case TARGET_F_RDAHEAD:
		 default:
			 ret = get_errno(fcntl(arg1, host_cmd, arg3));
			 break;
		 }
	 }
	 break;

    case TARGET_FREEBSD_NR_chroot:
	 if (!(p = lock_user_string(arg1)))
		 goto efault;
	 ret = get_errno(chroot(p));
	 unlock_user(p, arg1, 0);
	 break;

    case TARGET_FREEBSD_NR_getrusage:
	 {
		 struct rusage rusage;
		 ret = get_errno(getrusage(arg1, &rusage));
		 if (!is_error(ret))
			 host_to_target_rusage(arg2, &rusage);
	 }
	 break;

    case TARGET_FREEBSD_NR_wait4:
	 {
		 int status;
		 abi_long status_ptr = arg2;
		 struct rusage rusage, *rusage_ptr;
		 abi_ulong target_rusage = arg4;

		 if (target_rusage)
			 rusage_ptr = &rusage;
		 else
			 rusage_ptr = NULL;
		 ret = get_errno(wait4(arg1, &status, arg3, rusage_ptr));
		 if (!is_error(ret)) {
			 status = host_to_target_waitstatus(status);
			 if (put_user_s32(status, status_ptr))
				 goto efault;
			 if (target_rusage)
				 host_to_target_rusage(target_rusage, &rusage);
		 }
	 }
	 break;

    case TARGET_FREEBSD_NR_accept:
	 ret = do_accept(arg1, arg2, arg3);
	 break;

    case TARGET_FREEBSD_NR_bind:
	 ret = do_bind(arg1, arg2, arg3);
	 break;

    case TARGET_FREEBSD_NR_connect:
	 ret = do_connect(arg1, arg2, arg3);
	 break;

    case TARGET_FREEBSD_NR_getpeername:
	 ret = do_getpeername(arg1, arg2, arg3);
	 break;

    case TARGET_FREEBSD_NR_getsockname:
	 ret = do_getsockname(arg1, arg2, arg3);
	 break;

    case TARGET_FREEBSD_NR_getsockopt:
	 ret = do_getsockopt(arg1, arg2, arg3, arg4, arg5);
	 break;

    case TARGET_FREEBSD_NR_setsockopt:
	 ret = do_setsockopt(arg1, arg2, arg3, arg4, arg5);
	 break;

    case TARGET_FREEBSD_NR_listen:
	 ret = get_errno(listen(arg1, arg2));
	 break;

    case TARGET_FREEBSD_NR_recvfrom:
	 ret = do_recvfrom(arg1, arg2, arg3, arg4, arg5, arg6);
	 break;

    case TARGET_FREEBSD_NR_recvmsg:
	 ret = do_sendrecvmsg(arg1, arg2, arg3, 0);
	 break;

    case TARGET_FREEBSD_NR_sendmsg:
	 ret = do_sendrecvmsg(arg1, arg2, arg3, 1);
	 break;

    case TARGET_FREEBSD_NR_sendto:
	 ret = do_sendto(arg1, arg2, arg3, arg4, arg5, arg6);
	 break;

    case TARGET_FREEBSD_NR_socket:
	 ret = get_errno(socket(arg1, arg2, arg3));
	 break;

    case TARGET_FREEBSD_NR_socketpair:
	 ret = do_socketpair(arg1, arg2, arg3, arg4);
	 break;

    case TARGET_FREEBSD_NR_getpriority:
	 /*
	  * Note that negative values are valid for getpriority, so we must
	  * differentiate based on errno settings.
	  */
	 errno = 0;
	 ret = getpriority(arg1, arg2);
	 if (ret == -1 && errno != 0) {
		 ret = -host_to_target_errno(errno);
		 break;
	 }
	 /* Return value is a biased priority to avoid negative numbers. */
	 ret = 20 - ret;
	 break;

    case TARGET_FREEBSD_NR_setpriority:
	 ret = get_errno(setpriority(arg1, arg2, arg3));
	 break;

    case TARGET_FREEBSD_NR_kill:
    case TARGET_FREEBSD_NR_sigaction:
    case TARGET_FREEBSD_NR_sigprocmask:
    case TARGET_FREEBSD_NR_sigpending:
    case TARGET_FREEBSD_NR_sigsuspend:
    case TARGET_FREEBSD_NR_sigreturn:


    case TARGET_FREEBSD_NR_pselect:

    case TARGET_FREEBSD_NR_reboot:
    case TARGET_FREEBSD_NR_shutdown:

    case TARGET_FREEBSD_NR_swapon:
    case TARGET_FREEBSD_NR_swapoff:

    case TARGET_FREEBSD_NR_semget:
    case TARGET_FREEBSD_NR_semop:
    case TARGET_FREEBSD_NR___semctl:
    case TARGET_FREEBSD_NR_msgctl:
    case TARGET_FREEBSD_NR_msgrcv:
    case TARGET_FREEBSD_NR_msgsnd:
    case TARGET_FREEBSD_NR_shmget:
    case TARGET_FREEBSD_NR_shmctl:
    case TARGET_FREEBSD_NR_shmdt:

    case TARGET_FREEBSD_NR_getdents:
    case TARGET_FREEBSD_NR_getdirentries:

    case TARGET_FREEBSD_NR_poll:

    case TARGET_FREEBSD_NR_sendfile:

    case TARGET_FREEBSD_NR_fork:
    case TARGET_FREEBSD_NR_rfork:
    case TARGET_FREEBSD_NR_vfork:

    case TARGET_FREEBSD_NR_getgroups:
    case TARGET_FREEBSD_NR_setgroups:

    case TARGET_FREEBSD_NR_ptrace:
    case TARGET_FREEBSD_NR_ioctl:

    /* case TARGET_FREEBSD_NR_posix_fadvise: */

	ret = unimplemented(num);
	break;


    default:
        ret = get_errno(syscall(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8));
        break;
    }
 fail:
#ifdef DEBUG
    gemu_log(" = %ld\n", ret);
#endif
    if (do_strace)
        print_freebsd_syscall_ret(num, ret);
    return ret;
 efault:
    ret = -TARGET_EFAULT;
    goto fail;
}

abi_long do_netbsd_syscall(void *cpu_env, int num, abi_long arg1,
                           abi_long arg2, abi_long arg3, abi_long arg4,
                           abi_long arg5, abi_long arg6)
{
    abi_long ret;
    void *p;

#ifdef DEBUG
    gemu_log("netbsd syscall %d\n", num);
#endif
    if(do_strace)
        print_netbsd_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6);

    switch(num) {
    case TARGET_NETBSD_NR_exit:
#ifdef TARGET_GPROF
        _mcleanup();
#endif
        gdb_exit(cpu_env, arg1);
        /* XXX: should free thread stack and CPU env */
        _exit(arg1);
        ret = 0; /* avoid warning */
        break;
    case TARGET_NETBSD_NR_read:
        if (!(p = lock_user(VERIFY_WRITE, arg2, arg3, 0)))
            goto efault;
        ret = get_errno(read(arg1, p, arg3));
        unlock_user(p, arg2, ret);
        break;
    case TARGET_NETBSD_NR_write:
        if (!(p = lock_user(VERIFY_READ, arg2, arg3, 1)))
            goto efault;
        ret = get_errno(write(arg1, p, arg3));
        unlock_user(p, arg2, 0);
        break;
    case TARGET_NETBSD_NR_open:
        if (!(p = lock_user_string(arg1)))
            goto efault;
        ret = get_errno(open(path(p),
                             target_to_host_bitmask(arg2, fcntl_flags_tbl),
                             arg3));
        unlock_user(p, arg1, 0);
        break;
    case TARGET_NETBSD_NR_mmap:
        ret = get_errno(target_mmap(arg1, arg2, arg3,
                                    target_to_host_bitmask(arg4, mmap_flags_tbl),
                                    arg5,
                                    arg6));
        break;
    case TARGET_NETBSD_NR_mprotect:
        ret = get_errno(target_mprotect(arg1, arg2, arg3));
        break;
    case TARGET_NETBSD_NR_syscall:
    case TARGET_NETBSD_NR___syscall:
        ret = do_netbsd_syscall(cpu_env,arg1 & 0xffff,arg2,arg3,arg4,arg5,arg6,0);
        break;
    default:
        ret = syscall(num, arg1, arg2, arg3, arg4, arg5, arg6);
        break;
    }
 fail:
#ifdef DEBUG
    gemu_log(" = %ld\n", ret);
#endif
    if (do_strace)
        print_netbsd_syscall_ret(num, ret);
    return ret;
 efault:
    ret = -TARGET_EFAULT;
    goto fail;
}

abi_long do_openbsd_syscall(void *cpu_env, int num, abi_long arg1,
                            abi_long arg2, abi_long arg3, abi_long arg4,
                            abi_long arg5, abi_long arg6)
{
    abi_long ret;
    void *p;

#ifdef DEBUG
    gemu_log("openbsd syscall %d\n", num);
#endif
    if(do_strace)
        print_openbsd_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6);

    switch(num) {
    case TARGET_OPENBSD_NR_exit:
#ifdef TARGET_GPROF
        _mcleanup();
#endif
        gdb_exit(cpu_env, arg1);
        /* XXX: should free thread stack and CPU env */
        _exit(arg1);
        ret = 0; /* avoid warning */
        break;
    case TARGET_OPENBSD_NR_read:
        if (!(p = lock_user(VERIFY_WRITE, arg2, arg3, 0)))
            goto efault;
        ret = get_errno(read(arg1, p, arg3));
        unlock_user(p, arg2, ret);
        break;
    case TARGET_OPENBSD_NR_write:
        if (!(p = lock_user(VERIFY_READ, arg2, arg3, 1)))
            goto efault;
        ret = get_errno(write(arg1, p, arg3));
        unlock_user(p, arg2, 0);
        break;
    case TARGET_OPENBSD_NR_open:
        if (!(p = lock_user_string(arg1)))
            goto efault;
        ret = get_errno(open(path(p),
                             target_to_host_bitmask(arg2, fcntl_flags_tbl),
                             arg3));
        unlock_user(p, arg1, 0);
        break;
    case TARGET_OPENBSD_NR_mmap:
        ret = get_errno(target_mmap(arg1, arg2, arg3,
                                    target_to_host_bitmask(arg4, mmap_flags_tbl),
                                    arg5,
                                    arg6));
        break;
    case TARGET_OPENBSD_NR_mprotect:
        ret = get_errno(target_mprotect(arg1, arg2, arg3));
        break;
    case TARGET_OPENBSD_NR_syscall:
    case TARGET_OPENBSD_NR___syscall:
        ret = do_openbsd_syscall(cpu_env,arg1 & 0xffff,arg2,arg3,arg4,arg5,arg6,0);
        break;
    default:
        ret = syscall(num, arg1, arg2, arg3, arg4, arg5, arg6);
        break;
    }
 fail:
#ifdef DEBUG
    gemu_log(" = %ld\n", ret);
#endif
    if (do_strace)
        print_openbsd_syscall_ret(num, ret);
    return ret;
 efault:
    ret = -TARGET_EFAULT;
    goto fail;
}

void syscall_init(void)
{
}
