#ifndef TARGET_SIGNAL_H
#define TARGET_SIGNAL_H

#include "cpu.h"

static inline abi_ulong get_sp_from_cpustate(CPUARMState *state)
{
    return state->regs[13];
}

#define	TARGET_MINSIGSTKSZ	(1024 * 4)
#define	TARGET_SIGSTKSZ		(TARGET_MINSIGSTKSZ + 32768)

#endif /* TARGET_SIGNAL_H */
