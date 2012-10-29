#ifndef TARGET_SIGNAL_H
#define TARGET_SIGNAL_H

#include "cpu.h"

static inline abi_ulong get_sp_from_cpustate(CPUX86State *state)
{
    return state->regs[R_ESP];
}

#define	TARGET_SS_ONSTACK	0x0001	/* take signal on alternate stack */
#define	TARGET_SS_DISABLE	0x0004	/* disable taking signals on
					   alternate stack */

#define	TARGET_MINSIGSTKSZ	(512 * 4)
#define	TARGET_SIGSTKSZ		(TARGET_MINSIGSTKSZ + 32768)

#endif /* TARGET_SIGNAL_H */
