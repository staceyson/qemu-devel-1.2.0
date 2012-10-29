#ifndef TARGET_SIGNAL_H
#define TARGET_SIGNAL_H

#include "cpu.h"

#ifndef UREG_I6
#define UREG_I6        6
#endif
#ifndef UREG_FP
#define UREG_FP        UREG_I6
#endif

#define	TARGET_MINSIGSTKSZ	(512 * 4)
#define	TARGET_SIGSTKSZ		(TARGET_MINSIGSTKSZ + 32768)

static inline abi_ulong get_sp_from_cpustate(CPUSPARCState *state)
{
    return state->regwptr[UREG_FP];
}

#endif /* TARGET_SIGNAL_H */
