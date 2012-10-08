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
#include <utime.h>

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
fbsd_copy_from_user_timespec(struct timespec *ts, abi_ulong target_ts_addr)
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
fbsd_copy_to_user_timespec(struct timespec *ts, abi_ulong target_ts_addr)
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
    case TARGET_FREEBSD_NR_mlock:
    case TARGET_FREEBSD_NR_munlock:
    /* case TARGET_FREEBSD_NR_mlockall: */
    /* case TARGET_FREEBSD_NR_munlockall: */
    case TARGET_FREEBSD_NR_madvise:
	ret = unimplemented(num);
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

    case TARGET_FREEBSD_NR_clock_gettime:
	{
		struct timespec ts;

		ret = get_errno(clock_gettime(arg1, &ts));
		if (!is_error(ret)) {
			if (fbsd_copy_to_user_timespec(&ts, arg2))
				goto efault;
		}
    	}
        break;

   case TARGET_FREEBSD_NR_clock_getres:
	{
		struct timespec ts;
		ret = get_errno(clock_getres(arg1, &ts));
		if (!is_error(ret)) {
			if (fbsd_copy_to_user_timespec(&ts, arg2))
				goto efault;
		}
	}
	break;

    case TARGET_FREEBSD_NR_clock_settime:
	{
		struct timespec ts;
		if (fbsd_copy_from_user_timespec(&ts, arg2) != 0)
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
              if (fbsd_copy_from_user_timespec(&ts, arg6))
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


    case TARGET_FREEBSD_NR_ptrace:

    case TARGET_FREEBSD_NR_access:
    case TARGET_FREEBSD_NR_eaccess:
    case TARGET_FREEBSD_NR_faccessat:

    /* case TARGET_FREEBSD_NR_nice: */

    case TARGET_FREEBSD_NR_chdir:
    /* case TARGET_FREEBSD_NR_fchdir: */

    case TARGET_FREEBSD_NR_rename:
    case TARGET_FREEBSD_NR_renameat:

    case TARGET_FREEBSD_NR_link:
    case TARGET_FREEBSD_NR_linkat:

    case TARGET_FREEBSD_NR_unlink:
    case TARGET_FREEBSD_NR_unlinkat:

    case TARGET_FREEBSD_NR_mkdir:
    case TARGET_FREEBSD_NR_mkdirat:
    case TARGET_FREEBSD_NR_rmdir:

    /* case TARGET_FREEBSD_NR_dup: */

    case TARGET_FREEBSD_NR_sync:
    case TARGET_FREEBSD_NR_mount:
    case TARGET_FREEBSD_NR_unmount:
    case TARGET_FREEBSD_NR_nmount:

    case TARGET_FREEBSD_NR_ioctl:
    case TARGET_FREEBSD_NR_fcntl:

    /* case TARGET_FREEBSD_NR_umask: */

    case TARGET_FREEBSD_NR_chroot:

    case TARGET_FREEBSD_NR_kill:
    case TARGET_FREEBSD_NR_sigaction:
    case TARGET_FREEBSD_NR_sigprocmask:
    case TARGET_FREEBSD_NR_sigpending:
    case TARGET_FREEBSD_NR_sigsuspend:
    case TARGET_FREEBSD_NR_sigreturn:

    case TARGET_FREEBSD_NR_getrusage:

    case TARGET_FREEBSD_NR_pselect:

    case TARGET_FREEBSD_NR_symlink:
    case TARGET_FREEBSD_NR_symlinkat:

    case TARGET_FREEBSD_NR_readlink:
    case TARGET_FREEBSD_NR_readlinkat:

    case TARGET_FREEBSD_NR_reboot:
    case TARGET_FREEBSD_NR_shutdown:

    case TARGET_FREEBSD_NR_chmod:
    /* case TARGET_FREEBSD_NR_fchmod: */
    case TARGET_FREEBSD_NR_lchmod:
    case TARGET_FREEBSD_NR_fchmodat:

    case TARGET_FREEBSD_NR_mknod:
    case TARGET_FREEBSD_NR_mknodat:

    case TARGET_FREEBSD_NR_getpriority:
    case TARGET_FREEBSD_NR_setpriority:

    case TARGET_FREEBSD_NR_accept:
    case TARGET_FREEBSD_NR_bind:
    case TARGET_FREEBSD_NR_connect:
    case TARGET_FREEBSD_NR_getpeername:
    case TARGET_FREEBSD_NR_getsockname:
    case TARGET_FREEBSD_NR_getsockopt:
    /* case TARGET_FREEBSD_NR_listen: */
    case TARGET_FREEBSD_NR_recvfrom:
    case TARGET_FREEBSD_NR_recvmsg:
    case TARGET_FREEBSD_NR_sendmsg:
    case TARGET_FREEBSD_NR_sendto:
    /* case TARGET_FREEBSD_NR_socket: */
    case TARGET_FREEBSD_NR_socketpair:

    case TARGET_FREEBSD_NR_wait4:

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

    case TARGET_FREEBSD_NR_nanosleep:

    case TARGET_FREEBSD_NR___getcwd:

    case TARGET_FREEBSD_NR_sendfile:

    case TARGET_FREEBSD_NR_fork:
    case TARGET_FREEBSD_NR_rfork:
    case TARGET_FREEBSD_NR_vfork:

    case TARGET_FREEBSD_NR_truncate:
    case TARGET_FREEBSD_NR_ftruncate:

    case TARGET_FREEBSD_NR_chown:
    case TARGET_FREEBSD_NR_fchown:
    case TARGET_FREEBSD_NR_lchown:
    case TARGET_FREEBSD_NR_fchownat:

    case TARGET_FREEBSD_NR_getgroups:
    case TARGET_FREEBSD_NR_setgroups:

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
