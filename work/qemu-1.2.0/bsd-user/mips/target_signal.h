#ifndef TARGET_SIGNAL_H
#define TARGET_SIGNAL_H

#include "cpu.h"

/* this struct defines a stack used during syscall handling */

typedef struct target_sigaltstack {
	abi_long ss_sp;
	abi_ulong ss_size;
	abi_long ss_flags;
} target_stack_t;


#define TARGET_MINSIGSTKSZ    2048
#define TARGET_SIGSTKSZ       8192

static inline abi_ulong get_sp_from_cpustate(CPUMIPSState *state)
{
    return state->active_tc.gpr[29];
}

#endif /* TARGET_SIGNAL_H */
