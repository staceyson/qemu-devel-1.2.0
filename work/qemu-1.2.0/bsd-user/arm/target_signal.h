#ifndef TARGET_SIGNAL_H
#define TARGET_SIGNAL_H

#include "cpu.h"

static inline abi_ulong get_sp_from_cpustate(CPUARMState *state)
{
    return state->regs[13];
}

#define	TARGET_MINSIGSTKSZ	(1024 * 4)
#define	TARGET_SIGSTKSZ		(TARGET_MINSIGSTKSZ + 32768)

typedef target_ulong target_mcontext_t; /* dummy */

typedef struct target_ucontext {
	target_sigset_t		uc_sigmask;
	target_mcontext_t	uc_mcontext;
	abi_ulong		uc_link;
	target_stack_t		uc_stack;
	int32_t			uc_flags;
	int32_t			__spare__[4];
} target_ucontext_t;

static inline int
get_mcontext(CPUArchState *regs, target_mcontext_t *mcp, int flags)
{
	fprintf(stderr, "ARM doesn't have support for get_mcontext()\n");
	return (-TARGET_ENOSYS);
}

static inline int
set_mcontext(CPUArchState *regs, target_mcontext_t *mcp, int flags)
{
	fprintf(stderr, "ARM doesn't have support for set_mcontext()\n");
	return (-TARGET_ENOSYS);
}

#endif /* TARGET_SIGNAL_H */
