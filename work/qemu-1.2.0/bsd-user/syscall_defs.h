/*      $OpenBSD: signal.h,v 1.19 2006/01/08 14:20:16 millert Exp $     */
/*      $NetBSD: signal.h,v 1.21 1996/02/09 18:25:32 christos Exp $     */

/*
 * Copyright (c) 1982, 1986, 1989, 1991, 1993
 *      The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *      @(#)signal.h    8.2 (Berkeley) 1/21/94
 */

#define TARGET_SIGHUP  1       /* hangup */
#define TARGET_SIGINT  2       /* interrupt */
#define TARGET_SIGQUIT 3       /* quit */
#define TARGET_SIGILL  4       /* illegal instruction (not reset when caught) */
#define TARGET_SIGTRAP 5       /* trace trap (not reset when caught) */
#define TARGET_SIGABRT 6       /* abort() */
#define TARGET_SIGIOT  SIGABRT /* compatibility */
#define TARGET_SIGEMT  7       /* EMT instruction */
#define TARGET_SIGFPE  8       /* floating point exception */
#define TARGET_SIGKILL 9       /* kill (cannot be caught or ignored) */
#define TARGET_SIGBUS  10      /* bus error */
#define TARGET_SIGSEGV 11      /* segmentation violation */
#define TARGET_SIGSYS  12      /* bad argument to system call */
#define TARGET_SIGPIPE 13      /* write on a pipe with no one to read it */
#define TARGET_SIGALRM 14      /* alarm clock */
#define TARGET_SIGTERM 15      /* software termination signal from kill */
#define TARGET_SIGURG  16      /* urgent condition on IO channel */
#define TARGET_SIGSTOP 17      /* sendable stop signal not from tty */
#define TARGET_SIGTSTP 18      /* stop signal from tty */
#define TARGET_SIGCONT 19      /* continue a stopped process */
#define TARGET_SIGCHLD 20      /* to parent on child stop or exit */
#define TARGET_SIGTTIN 21      /* to readers pgrp upon background tty read */
#define TARGET_SIGTTOU 22      /* like TTIN for output if (tp->t_local&LTOSTOP) */
#define TARGET_SIGIO   23      /* input/output possible signal */
#define TARGET_SIGXCPU 24      /* exceeded CPU time limit */
#define TARGET_SIGXFSZ 25      /* exceeded file size limit */
#define TARGET_SIGVTALRM 26    /* virtual time alarm */
#define TARGET_SIGPROF 27      /* profiling time alarm */
#define TARGET_SIGWINCH 28      /* window size changes */
#define TARGET_SIGINFO  29      /* information request */
#define TARGET_SIGUSR1 30       /* user defined signal 1 */
#define TARGET_SIGUSR2 31       /* user defined signal 2 */
#define	TARGET_SIGTHR 32	/* reserved by thread library */
#define	TARGET_SIGLWP SIGTHR	/* compatibility */
#define	TARGET_SIGLIBRT 33	/* reserved by the real-time library */
#define	TARGET_SIGRTMIN 65
#define	TARGET_SIGRTMAX	126
#define	TARGET_QEMU_ESIGRETURN	255	/* fake errno value for use by sigreturn */


/*
 * Language spec says we must list exactly one parameter, even though we
 * actually supply three.  Ugh!
 */
#define	TARGET_SIG_DFL		((abi_long)0)	/* default signal handling */
#define TARGET_SIG_IGN		((abi_long)1)	/* ignore signal */
#define	TARGET_SIG_ERR		((abi_long)-1)	/* error return from signal */

#define TARGET_SA_ONSTACK       0x0001  /* take signal on signal stack */
#define TARGET_SA_RESTART       0x0002  /* restart system on signal return */
#define TARGET_SA_RESETHAND     0x0004  /* reset to SIG_DFL when taking signal */
#define TARGET_SA_NODEFER       0x0010  /* don't mask the signal we're delivering */
#define TARGET_SA_NOCLDWAIT     0x0020  /* don't create zombies (assign to pid 1) */
#define TARGET_SA_USERTRAMP    0x0100  /* do not bounce off kernel's sigtramp */
#define TARGET_SA_NOCLDSTOP     0x0008  /* do not generate SIGCHLD on child stop */
#define TARGET_SA_SIGINFO       0x0040  /* generate siginfo_t */

/*
 * Flags for sigprocmask:
 */
#define TARGET_SIG_BLOCK       1       /* block specified signal set */
#define TARGET_SIG_UNBLOCK     2       /* unblock specified signal set */
#define TARGET_SIG_SETMASK     3       /* set specified signal set */

#define TARGET_BADSIG          SIG_ERR

#define TARGET_SS_ONSTACK       0x0001  /* take signals on alternate stack */
#define TARGET_SS_DISABLE       0x0004  /* disable taking signals on alternate stack */

/*
 * si_code values
 * Digital reserves positive values for kernel-generated signals.
 */

/*
 * SIGSEGV si_codes
 */
#define TARGET_SEGV_MAPERR	(1)	/* address not mapped to object */
#define	TARGET_SEGV_ACCERR	(2)	/* invalid permissions for mapped
					   object */
/*
 * SIGTRAP si_codes
 */
#define	TARGET_TRAP_BRKPT	(1)	/* process beakpoint */
#define	TARGET_TRAP_TRACE	(2)	/* process trace trap */

struct target_rlimit {
	abi_ulong rlim_cur;
	abi_ulong rlim_max;
};

#if defined(TARGET_ALPHA)
#define	TARGET_RLIM_INFINITY	0x7fffffffffffffffull
#elif defined(TARGET_MIPS) || (defined(TARGET_SPARC) && TARGET_ABI_BITS == 32)
#define	TARGET_RLIM_INFINITY	0x7fffffffUL
#else
#define	TARGET_RLIM_INFINITY	((abi_ulong)-1)
#endif

#define TARGET_RLIMIT_CPU	0
#define TARGET_RLIMIT_FSIZE	1
#define TARGET_RLIMIT_DATA	2
#define TARGET_RLIMIT_STACK	3
#define TARGET_RLIMIT_CORE	4
#define TARGET_RLIMIT_RSS	5
#define TARGET_RLIMIT_MEMLOCK	6
#define TARGET_RLIMIT_NPROC	7
#define TARGET_RLIMIT_NOFILE	8
#define TARGET_RLIMIT_SBSIZE	9
#define TARGET_RLIMIT_AS	10
#define TARGET_RLIMIT_NPTS	11
#define TARGET_RLIMIT_SWAP	12

/*
 * Constants used for fcntl(2).
 */

/* command values */
#define	TARGET_F_DUPFD		0
#define	TARGET_F_GETFD		1
#define	TARGET_F_SETFD		2
#define	TARGET_F_GETFL		3
#define	TARGET_F_SETFL		4
#define	TARGET_F_GETOWN		5
#define	TARGET_F_SETOWN		6
#define	TARGET_F_OGETLK		7
#define	TARGET_F_OSETLK		8
#define	TARGET_F_OSETLKW	9
#define	TARGET_F_DUP2FD		10
#define	TARGET_F_GETLK		11
#define	TARGET_F_SETLK		12
#define	TARGET_F_SETLKW		13
#define	TARGET_F_SETLK_REMOTE	14
#define	TARGET_F_READAHEAD	15
#define	TARGET_F_RDAHEAD	16

#define	TARGET_O_NONBLOCK	0x00000004 
#define	TARGET_O_APPEND		0x00000008
#define	TARGET_O_ASYNC		0x00000040
#define	TARGET_O_DIRECT		0x00010000

#include "errno_defs.h"

#include "freebsd/syscall_nr.h"
#include "netbsd/syscall_nr.h"
#include "openbsd/syscall_nr.h"

struct target_flock {
    unsigned long long l_start;
    unsigned long long l_len;
    int l_pid;
    int l_sysid;
    short l_type;
    short l_whence;
} QEMU_PACKED;

struct target_iovec {
    abi_long iov_base;   /* Starting address */
    abi_long iov_len;   /* Number of bytes */
};

struct target_timeval {
	abi_long tv_sec;
	abi_long tv_usec;
};

typedef abi_long target_clock_t;

#define	TARGET_NSIG		128
#define	TARGET_NSIG_BPW		TARGET_ABI_BITS
#define	TARGET_NSIG_WORDS	(TARGET_NSIG / TARGET_NSIG_BPW)

typedef struct {
	abi_ulong sig[TARGET_NSIG_WORDS];
} target_sigset_t;

struct target_rusage {
	struct target_timeval ru_utime;	/* user time used */
	struct target_timeval ru_stime;	/* system time used */
	abi_long    ru_maxrss;		/* maximum resident set size */
	abi_long    ru_ixrss;		/* integral shared memory size */
	abi_long    ru_idrss;		/* integral unshared data size */
	abi_long    ru_isrss;		/* integral unshared stack size */
	abi_long    ru_minflt;		/* page reclaims */
	abi_long    ru_majflt;		/* page faults */
	abi_long    ru_nswap;		/* swaps */
	abi_long    ru_inblock;		/* block input operations */
	abi_long    ru_oublock;		/* block output operations */
	abi_long    ru_msgsnd;		/* messages sent */
	abi_long    ru_msgrcv;		/* messages received */
	abi_long    ru_nsignals;	/* signals received */
	abi_long    ru_nvcsw;		/* voluntary context switches */
	abi_long    ru_nivcsw;		/* involuntary context switches */
};

#ifdef BSWAP_NEEDED
static inline void
tswap_sigset(target_sigset_t *d, const target_sigset_t *s)
{
	int i;

	for(i = 0; i < TARGET_NSIG_WORDS; i++)
		d->sig[i] = tswapal(s->sig[i]);
}
#else
static inline void
tswap_sigset(target_sigset_t *d, const target_sigset_t *s)
{
	*d = *s;
}
#endif

static inline void
target_siginitset(target_sigset_t *d, abi_ulong set)
{
	int i;

	d->sig[0] = set;
	for(i = 1; i < TARGET_NSIG_WORDS; i++)
		d->sig[i] = 0;
}

void host_to_target_sigset(target_sigset_t *d, const sigset_t *s);
void target_to_host_sigset(sigset_t *d, const target_sigset_t *s);
void host_to_target_old_sigset(abi_ulong *old_sigset, const sigset_t *sigset);
void target_to_host_old_sigset(sigset_t *sigset, const abi_ulong *old_sigset);
struct target_sigaction;
int do_sigaction(int sig, const struct target_sigaction *act,
    struct target_sigaction *oact);


struct target_sigaction {
	abi_ulong	 _sa_handler;
	abi_ulong	sa_flags;
	target_sigset_t	sa_mask;
};

typedef union target_sigval {
	int sival_int;
	abi_ulong sival_ptr;
} target_sigval_t;

#define	TARGET_SI_MAX_SIZE	128
#define TARGET_SI_PAD_SIZE	((TARGET_SI_MAX_SIZE/sizeof(int)) - 3)

typedef struct target_siginfo {
#ifdef TARGET_MIPS
	int si_signo;
	int si_code;
	int si_errno;
#else
	int si_signo;
	int si_errno;
	int si_code;
#endif
	union {
		int _pad[TARGET_SI_PAD_SIZE];

		/* kill() */
		struct {
			pid_t _pid;	/* sender's pid */
			uid_t _uid;	/* sender's uid */
		} _kill;

		/* POSIX.1b timers */
		struct {
			unsigned int _timer1;
			unsigned int _timer2;
		} _timer;

		/* POSIX.1b signals */
		struct {
			pid_t _pid;	/* sender's pid */
			uid_t _uid;	/* sender's uid */
			target_sigval_t _sigval;
		} _rt;

		/* SIGCHLD */
		struct {
			pid_t _pid;	/* which child */
			uid_t _uid;	/* sender's uid */
			int  _status;	/* exit code */
			target_clock_t _utime;
			target_clock_t _stime;
		} _sigchld;

		/* SIGILL, SIGFPE, SIGSEGV, SIGBUS */
		struct {
			abi_ulong _addr; /* faulting insn/memory ref. */
		} _sigfault;

		/* SIGPOLL */
		struct {
			int _band;	/* POLL_IN, POLL_OUT, POLL_MSG */
			int _fd;
		} _sigpoll;
	} _sifields;
} target_siginfo_t;

struct target_kevent {
    abi_ulong  ident;
    short      filter;
    u_short    flags;
    u_int      fflags;
    abi_long   data;
    abi_ulong  udata;
} __packed;

/*
 * FreeBSD/arm uses a 64bits time_t, even in 32bits mode, so we have to
 * add a special case here.
 */
#if defined(TARGET_ARM)
typedef uint64_t target_freebsd_time_t;
#else
typedef long target_freebsd_time_t;
#endif

struct target_freebsd_timespec {
	target_freebsd_time_t	tv_sec;		/* seconds */
	abi_long		tv_nsec;	/* and nanoseconds */
} __packed;

struct target_freebsd_timeval {
	target_freebsd_time_t	tv_sec;
	abi_long		tv_usec;
} __packed;

struct target_freebsd_stat {
	uint32_t  st_dev;		/* inode's device */
	uint32_t  st_ino;		/* inode's number */
	int16_t	  st_mode;		/* inode protection mode */
	int16_t	  st_nlink;		/* number of hard links */
	uint32_t  st_uid;		/* user ID of the file's owner */
	uint32_t  st_gid;		/* group ID of the file's group */
	uint32_t  st_rdev;		/* device type */
	struct	target_freebsd_timespec st_atim;	/* time of last access */
	struct	target_freebsd_timespec st_mtim;	/* time of last data modification */
	struct	target_freebsd_timespec st_ctim;	/* time of last file status change */
	int64_t	  st_size;		/* file size, in bytes */
	int64_t st_blocks;		/* blocks allocated for file */
	uint32_t st_blksize;		/* optimal blocksize for I/O */
	uint32_t  st_flags;		/* user defined flags for file */
	__uint32_t st_gen;		/* file generation number */
	__int32_t st_lspare;
	struct target_freebsd_timespec st_birthtim;	/* time of file creation */
	/*
	 * Explicitly pad st_birthtim to 16 bytes so that the size of
	 * struct stat is backwards compatible.  We use bitfields instead
	 * of an array of chars so that this doesn't require a C99 compiler
	 * to compile if the size of the padding is 0.  We use 2 bitfields
	 * to cover up to 64 bits on 32-bit machines.  We assume that
	 * CHAR_BIT is 8...
	 */
	unsigned int :(8 / 2) * (16 - (int)sizeof(struct timespec));
	unsigned int :(8 / 2) * (16 - (int)sizeof(struct timespec));
} __packed;

