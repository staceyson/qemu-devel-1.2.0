#ifndef TARGET_SIGNAL_H
#define TARGET_SIGNAL_H

#include "cpu.h"

#define	TARGET_MINSIGSTKSZ	(512 * 4)
#define	TARGET_SIGSTKSZ		(TARGET_MINSIGSTKSZ + 32768)

static inline abi_ulong get_sp_from_cpustate(CPUMIPSState *state)
{
    return state->active_tc.gpr[29];
}

#endif /* TARGET_SIGNAL_H */
