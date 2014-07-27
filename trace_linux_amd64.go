package libtrace

import "syscall"

type SyscallId uint64

func (t *tracerImpl) callback(regs syscall.PtraceRegs, exit bool) {
	t.callback_generic(SyscallId(regs.Orig_rax), exit)
}
