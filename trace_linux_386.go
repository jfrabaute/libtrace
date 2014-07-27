package libtrace

import "syscall"

type SyscallId int32

func (t *tracerImpl) callback(regs syscall.PtraceRegs, exit bool) {
	t.callback_generic(SyscallId(regs.Orig_eax), exit)
}
