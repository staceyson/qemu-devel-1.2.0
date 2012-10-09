/*
 *  Emulation of BSD signals
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
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#include "qemu.h"
#include "target_signal.h"

//#define DEBUG_SIGNAL

#ifndef _NSIG
#define _NSIG	128
#endif

static uint8_t host_to_target_signal_table[_NSIG] = {
	[SIGHUP] 	= 	TARGET_SIGHUP,
	[SIGINT] 	= 	TARGET_SIGINT,
	[SIGQUIT]	= 	TARGET_SIGQUIT,
	[SIGILL]	=	TARGET_SIGILL,
	[SIGTRAP]	=	TARGET_SIGTRAP,
	[SIGABRT]	=	TARGET_SIGABRT,
	/* [SIGIOT]	=	TARGET_SIGIOT, */
	[SIGEMT]	=	TARGET_SIGEMT,
	[SIGFPE]	=	TARGET_SIGFPE,
	[SIGKILL]	=	TARGET_SIGKILL,
	[SIGBUS]	=	TARGET_SIGBUS,
	[SIGSEGV]	=	TARGET_SIGSEGV,
	[SIGSYS]	=	TARGET_SIGSYS,
	[SIGPIPE]	=	TARGET_SIGPIPE,
	[SIGALRM]	=	TARGET_SIGALRM,
	[SIGTERM]	=	TARGET_SIGTERM,
	[SIGURG]	=	TARGET_SIGURG,
	[SIGSTOP]	=	TARGET_SIGSTOP,
	[SIGTSTP]	=	TARGET_SIGTSTP,
	[SIGCONT]	=	TARGET_SIGCONT,
	[SIGCHLD]	=	TARGET_SIGCHLD,
	[SIGTTIN]	=	TARGET_SIGTTIN,
	[SIGTTOU]	=	TARGET_SIGTTOU,
	[SIGIO]		=	TARGET_SIGIO,
	[SIGXCPU]	=	TARGET_SIGXCPU,
	[SIGXFSZ]	=	TARGET_SIGXFSZ,
	[SIGVTALRM]	=	TARGET_SIGALRM,
	[SIGPROF]	=	TARGET_SIGPROF,
	[SIGWINCH]	=	TARGET_SIGWINCH,
	[SIGINFO]	=	TARGET_SIGINFO,
	[SIGUSR1]	=	TARGET_SIGUSR1,
	[SIGUSR2]	=	TARGET_SIGUSR2,
#ifdef SIGTHR
	[SIGTHR]	=	TARGET_SIGTHR,
#endif
	/* [SIGLWP]	=	TARGET_SIGLWP, */
#ifdef SIGLIBRT
	[SIGLIBRT]	=	TARGET_SIGLIBRT,
#endif

	/*
	 * The following signals stay the same.
	 * Nasty hack: Reverse SIGRTMIN and SIGRTMAX to avoid overlap with
	 * host libpthread signals.  This assumes no one actually uses
	 * SIGRTMAX.  To fix this properly we need to manual signal delivery
	 * multiplexed over a single host signal.
	 */
	[SIGRTMIN]	=	SIGRTMAX,
	[SIGRTMAX]	=	SIGRTMIN,
};

static uint8_t target_to_host_signal_table[_NSIG];

static struct target_sigaction sigact_table[TARGET_NSIG];

static void host_signal_handler(int host_signum, siginfo_t *info, void *puc);
static int target_to_host_signal(int sig);

int
host_to_target_signal(int sig)
{

	if (sig >= _NSIG)
		return (sig);
	return (host_to_target_signal_table[sig]);
}

static int
target_to_host_signal(int sig)
{

	if (sig >= _NSIG)
		return (sig);
	return (target_to_host_signal_table[sig]);
}

static inline void
target_sigemptyset(target_sigset_t *set)
{
	memset(set, 0, sizeof(*set));
}

static inline void
target_sigaddset(target_sigset_t *set, int signum)
{
	signum--;
	abi_ulong mask = (abi_ulong)1 << (signum % TARGET_NSIG_BPW);
	set->sig[signum / TARGET_NSIG_BPW] |= mask;
}

static inline int
target_sigismember(const target_sigset_t *set, int signum)
{
	signum--;
	abi_ulong mask = (abi_ulong)1 << (signum % TARGET_NSIG_BPW);
	return ((set->sig[signum / TARGET_NSIG_BPW] & mask) != 0);
}

static void
host_to_target_sigset_internal(target_sigset_t *d, const sigset_t *s)
{
	int i;

	target_sigemptyset(d);
	for (i = 1; i <= TARGET_NSIG; i++) {
		if (sigismember(s, i)) {
			target_sigaddset(d, host_to_target_signal(i));
		}
	}
}

void
host_to_target_sigset(target_sigset_t *d, const sigset_t *s)
{
	target_sigset_t d1;
	int i;

	host_to_target_sigset_internal(&d1, s);
	for(i = 0;i < TARGET_NSIG_WORDS; i++)
		d->sig[i] = tswapal(d1.sig[i]);
}

static void
target_to_host_sigset_internal(sigset_t *d, const target_sigset_t *s)
{
	int i;

	sigemptyset(d);
	for (i = 1; i <= TARGET_NSIG; i++) {
		if (target_sigismember(s, i)) {
			sigaddset(d, target_to_host_signal(i));
		}
	}
}

void
target_to_host_sigset(sigset_t *d, const target_sigset_t *s)
{
	target_sigset_t s1;
	int i;

	for(i = 0; i < TARGET_NSIG_WORDS; i++)
		s1.sig[i] = tswapal(s->sig[i]);
	target_to_host_sigset_internal(d, &s1);
}

/* Siginfo conversion. */
static inline void
host_to_target_siginfo_noswap(target_siginfo_t *tinfo, const siginfo_t *info)
{
	int sig;

	sig = host_to_target_signal(info->si_signo);
	tinfo->si_signo = sig;
	tinfo->si_errno = 0;
	tinfo->si_code = info->si_code;
	if (SIGILL == sig || SIGFPE == sig || SIGSEGV == sig ||
	    SIGBUS == sig || SIGTRAP == sig) {
		/*
		 * Should never come here but who knows.  The information for
		 * the target is irrelevant.
		 */
		tinfo->_sifields._sigfault._addr = 0;
#if 0
	} else if (SIGIO == sig) {
		tinfo->_sifields._sigpoll._fd = info->si_fd;
#endif
	} else if (sig >= TARGET_SIGRTMIN) {
		tinfo->_sifields._rt._pid = info->si_pid;
		tinfo->_sifields._rt._uid = info->si_uid;
		/* XXX: potential problem if 64 bit */
		tinfo->_sifields._rt._sigval.sival_ptr =
		    (abi_ulong)(unsigned long)info->si_value.sival_ptr;
	}
}

/* Returns 1 if given signal should dump core if not handled. */
static int
core_dump_signal(int sig)
{
	switch (sig) {
	case TARGET_SIGABRT:
	case TARGET_SIGFPE:
	case TARGET_SIGILL:
	case TARGET_SIGQUIT:
	case TARGET_SIGSEGV:
	case TARGET_SIGTRAP:
	case TARGET_SIGBUS:
		return (1);
	default:
		return (0);
	}
}

/* Signal queue handling. */
static inline struct sigqueue *
alloc_sigqueue(CPUArchState *env)
{
	TaskState *ts = env->opaque;
	struct sigqueue *q = ts->first_free;

	if (!q)
		return (NULL);
	ts->first_free = q->next;
	return (q);
}

static inline void
free_sigqueue(CPUArchState *env, struct sigqueue *q)
{

	TaskState *ts = env->opaque;
	q->next = ts->first_free;
	ts->first_free = q;
}

/* Abort execution with signal. */
static void QEMU_NORETURN
force_sig(int target_sig)
{
	TaskState *ts = (TaskState *)thread_env->opaque;
	int host_sig, core_dumped = 0;
	struct sigaction act;

	host_sig = target_to_host_signal(target_sig);
	gdb_signalled(thread_env, target_sig);

	/* Dump core if supported by target binary format */
	if (core_dump_signal(target_sig) && (ts->bprm->core_dump != NULL)) {
		stop_all_tasks();
		core_dumped =
		    ((*ts->bprm->core_dump)(target_sig, thread_env) == 0);
	}
	if (core_dumped) {
		struct rlimit nodump;

		/*
		 * We already dumped the core of target process, we don't want
		 * a coredump of qemu itself.
		 */
		 getrlimit(RLIMIT_CORE, &nodump);
		 nodump.rlim_cur = 0;
		 (void) fprintf(stderr, "qemu: uncaught target signal %d (%s) "
		     "- %s\n", target_sig, strsignal(host_sig), "core dumped");
	}

	/*
	 * The proper exit code for dying from an uncaught signal is
	 * -<signal>.  The kernel doesn't allow exit() or _exit() to pass
	 * a negative value.  To get the proper exit code we need to
	 * actually die from an uncaught signal.  Here the default signal
	 * handler is installed, we send ourself a signal and we wait for
	 * it to arrive.
	 */
	sigfillset(&act.sa_mask);
	act.sa_handler = SIG_DFL;
	sigaction(host_sig, &act, NULL);

	if (raise(host_sig) != 0)
		kill(getpid(), host_sig);

	/*
	 * Make sure the signal isn't masked (just reuse the mask inside
	 * of act).
	 */
	sigdelset(&act.sa_mask, host_sig);
	sigsuspend(&act.sa_mask);

	/* unreachable */
	abort();
}

/*
 * Queue a signal so that it will be send to the virtual CPU as soon as
 * possible.
 */
int
queue_signal(CPUArchState *env, int sig, target_siginfo_t *info)
{
	TaskState *ts = env->opaque;
	struct emulated_sigtable *k;
	struct sigqueue *q, **pq;
	abi_ulong handler;
	int queue;

#ifdef DEBUG_SIGNAL
	fprintf(stderr, "queue_signal: sig=%d\n", sig);
#endif
	k = &ts->sigtab[sig - 1];
	queue = gdb_queuesig ();
	handler = sigact_table[sig - 1]._sa_handler;
	if (!queue && TARGET_SIG_DFL == handler) {
		if (sig == TARGET_SIGTSTP || sig == TARGET_SIGTTIN ||
		    sig == TARGET_SIGTTOU) {
			kill(getpid(), SIGSTOP);
			return (0);
		} else
			if (sig != TARGET_SIGCHLD &&
			    sig != TARGET_SIGURG &&
			    sig != TARGET_SIGWINCH &&
			    sig != TARGET_SIGCONT) {
				force_sig(sig);
			} else {
				return (0); /* The signal was ignored. */
			}
	} else if (!queue && TARGET_SIG_IGN == handler) {
		return (0); /* The signal was ignored. */
	} else if (!queue && TARGET_SIG_ERR == handler) {
		force_sig(sig);
	} else if (!queue && TARGET_SIG_ERR == handler) {
		force_sig(sig);
	} else {
		pq = &k->first;
		if (sig < TARGET_SIGRTMIN) {
			/*
			 * If non real time signal then queue exactly one
			 * signal.
			 */
			if (!k->pending)
				 q = &k->info;
			else
				return (0);
		} else {
			if (!k->pending) {
				/* first signal */
				q = &k->info;
			} else {
				q = alloc_sigqueue(env);
				if (!q)
					return (-EAGAIN);
				while (*pq != NULL)
					pq = &(*pq)->next;
			}
		}
		*pq = q;
		q->info = *info;
		q->next = NULL;
		k->pending = 1;
		/* Signal that a new signal is pending. */
		ts->signal_pending = 1;
		return (1); /* Indicates that the signal was queued. */
	}
}

static void
host_signal_handler(int host_signum, siginfo_t *info, void *puc)
{
	int sig;
	target_siginfo_t tinfo;

	/*
	 * The CPU emulator uses some host signal to detect exceptions so
	 * we forward to it some signals.
	 */
	if ((host_signum == SIGSEGV || host_signum == SIGBUS) &&
	    info->si_code > 0) {
		if (cpu_signal_handler(host_signum, info, puc))
			return;
	}

	/* Get the target signal number. */
	sig = host_to_target_signal(host_signum);
	if (sig < 1 || sig > TARGET_NSIG)
		return;
#ifdef DEBUG_SIGNAL
	fprintf(stderr, "qemu: got signal %d\n", sig);
#endif
	host_to_target_siginfo_noswap(&tinfo, info);
	if (queue_signal(thread_env, sig, &tinfo) == 1) {
		/* Interrupt the virtual CPU as soon as possible. */
		cpu_exit(thread_env);
	}
}

static void
setup_frame(int sig, struct target_sigaction *ka, target_sigset_t *set,
    CPUArchState *env)
{
	fprintf(stderr, "setup_frame: not implemented\n");
}

static void
setup_rt_frame(int sig, struct target_sigaction *ka, target_siginfo_t *info,
    target_sigset_t *set, CPUArchState *env)
{
	fprintf(stderr, "setup_rt_frame: not implemented\n");
}

long
do_sigreturn(CPUArchState *env)
{
	fprintf(stderr,"do_sigreturn: not implemented\n");
	return (-TARGET_ENOSYS);
}

long
do_rt_sigreturn(CPUArchState *env)
{
	fprintf(stderr, "do_rt_sigreturn: not implemented\n");
	return (-TARGET_ENOSYS);
}


static int
fatal_signal(int sig)
{

	switch (sig) {
	case TARGET_SIGCHLD:
	case TARGET_SIGURG:
	case TARGET_SIGWINCH:
		/* Ignored by default. */
		return (0);
	case TARGET_SIGCONT:
	case TARGET_SIGSTOP:
	case TARGET_SIGTSTP:
	case TARGET_SIGTTIN:
	case TARGET_SIGTTOU:
		/* Job control signals.  */
		return (0);
	default:
		return (1);
	}
}

void
signal_init(void)
{
	struct sigaction act;
	struct sigaction oact;
	int i, j;
	int host_sig;

	/* Generate the signal conversion tables.  */
	for(i = 1; i < _NSIG; i++) {
		if (host_to_target_signal_table[i] == 0)
			host_to_target_signal_table[i] = i;
	}
	for(i = 1; i < _NSIG; i++) {
		j = host_to_target_signal_table[i];
		target_to_host_signal_table[j] = i;
	}

	/*
	 * Set all host signal handlers. ALL signals are blocked during the
	 * handlers to serialize them.
	 */
	memset(sigact_table, 0, sizeof(sigact_table));

	sigfillset(&act.sa_mask);
	act.sa_sigaction = host_signal_handler;

	for (i = 1; i <= TARGET_NSIG; i++) {
		host_sig = target_to_host_signal(i);
		sigaction(host_sig, NULL, &oact);
		if (oact.sa_sigaction == (void *)SIG_IGN) {
			sigact_table[i - 1]._sa_handler = TARGET_SIG_IGN;
		} else if (oact.sa_sigaction == (void *)SIG_DFL) {
			sigact_table[i - 1]._sa_handler = TARGET_SIG_DFL;
		}
		/*
		 * If there's already a handler installed then something has
		 * gone horribly wrong, so don't even try to handle that case.
		 * Install some handlers for our own use.  We need at least
		 * SIGSEGV and SIGBUS, to detect exceptions.  We can not just
		 * trap all signals because it affects syscall interrupt
		 * behavior.  But do trap all default-fatal signals.
		 */
		if (fatal_signal(i))
			sigaction(host_sig, &act, NULL);
	}
}

void
process_pending_signals(CPUArchState *cpu_env)
{
	int sig;
	abi_ulong handler;
	sigset_t set, old_set;
	target_sigset_t target_old_set;
	struct emulated_sigtable *k;
	struct target_sigaction *sa;
	struct sigqueue *q;
	TaskState *ts = cpu_env->opaque;

	if (!ts->signal_pending)
		return;

	/* FIXME: This is not threadsafe.  */
	k  = ts->sigtab;
	for(sig = 1; sig <= TARGET_NSIG; sig++) {
		if (k->pending)
			goto handle_signal;
		k++;
	}

	/* If no signal is pending then just return. */
	ts->signal_pending = 0;
	return;

handle_signal:
#ifdef DEBUG_SIGNAL
	fprintf(stderr, "qemu: process signal %d\n", sig);
#endif

	/* Dequeue signal. */
	q = k->first;
	k->first = q->next;
	if (!k->first)
		k->pending = 0;

	sig = gdb_handlesig (cpu_env, sig);
	if (!sig) {
		sa = NULL;
		handler = TARGET_SIG_IGN;
	} else {
		sa = &sigact_table[sig - 1];
		handler = sa->_sa_handler;
	}

	if (handler == TARGET_SIG_DFL) {
		/*
		 * default handler : ignore some signal. The other are job
		 * control or fatal.
		 */
		if (TARGET_SIGTSTP == sig || TARGET_SIGTTIN == sig ||
		    TARGET_SIGTTOU == sig) {
			kill(getpid(),SIGSTOP);
		} else if (TARGET_SIGCHLD != sig && TARGET_SIGURG != sig &&
		    TARGET_SIGWINCH != sig && TARGET_SIGCONT != sig) {
			force_sig(sig);
		}
	} else if (TARGET_SIG_IGN == handler) {
		/* ignore sig */
	} else if (TARGET_SIG_ERR == handler) {
		/* compute the blocked signals during the handler execution */
		target_to_host_sigset(&set, &sa->sa_mask);
		/*
		 * SA_NODEFER indicates that the current signal should not be
		 * blocked during the handler.
		 */
		if (!(sa->sa_flags & TARGET_SA_NODEFER))
			sigaddset(&set, target_to_host_signal(sig));

		/* block signals in the handler */
		sigprocmask(SIG_BLOCK, &set, &old_set);

		/*
		 * Save the previous blocked signal state to restore it at the
		 * end of the signal execution (see do_sigreturn).
		 */
		host_to_target_sigset_internal(&target_old_set, &old_set);

#if 0
#if defined(TARGET_I386) && !defined(TARGET_X86_64)
		/* if the CPU is in VM86 mode, we restore the 32 bit values */
		{
			CPUX86State *env = cpu_env;
			if (env->eflags & VM_MASK)
				save_v86_state(env);
		}
#endif
#endif
		/* prepare the stack frame of the virtual CPU */
		 if (sa->sa_flags & TARGET_SA_SIGINFO)
			 setup_rt_frame(sig, sa, &q->info, &target_old_set,
			     cpu_env);
		 else
			 setup_frame(sig, sa, &target_old_set, cpu_env);
		 if (sa->sa_flags & TARGET_SA_RESETHAND)
			 sa->_sa_handler = TARGET_SIG_DFL;
	}
	if (q != &k->info)
		free_sigqueue(cpu_env, q);
}
