package libtrace

import (
	"log"
	"syscall"
)

type SyscallId uint64

type ExitCode int32

type regParam uint64

// Get the value of the param (0 from 5 allowed)
func getParam(regs syscall.PtraceRegs, i int) regParam {
	switch i {
	case 0:
		return regParam(regs.Rdi)
	case 1:
		return regParam(regs.Rsi)
	case 2:
		return regParam(regs.Rdx)
	case 3:
		return regParam(regs.Rcx)
	case 4:
		return regParam(regs.R8)
	case 5:
		return regParam(regs.R9)
	}
	log.Fatalf("index out of range: %d", i)
	return 0
}

func getExitCode(regs syscall.PtraceRegs) ExitCode {
	return ExitCode(regs.Rax)
}

func getSyscallId(regs syscall.PtraceRegs) SyscallId {
	return SyscallId(regs.Orig_rax)
}

func (t *tracerImpl) callback(regs syscall.PtraceRegs, exit bool) {
	// params: %rdi, %rsi, %rdx, %rcx, %r8, %r9
	t.callback_generic(regs, exit)
}
