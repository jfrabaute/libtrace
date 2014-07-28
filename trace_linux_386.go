package libtrace

import (
	"log"
	"syscall"
)

type SyscallId int32

type ExitCode int32

type regParam int32

func getParam(regs syscall.PtraceRegs, i int) regParam {
	switch i {
	case 0:
		return regParam(regs.Ebx)
	case 1:
		return regParam(regs.Ecx)
	case 2:
		return regParam(regs.Edx)
	case 3:
		return regParam(regs.Esi)
	case 4:
		return regParam(regs.Edi)
	case 5:
		return regParam(regs.Ebp)
	}
	log.Fatalf("index out of range: %d", i)
	return 0
}

func getExitCode(regs syscall.PtraceRegs) ExitCode {
	return ExitCode(regs.Eax)
}

func getSyscallId(regs syscall.PtraceRegs) SyscallId {
	return SyscallId(regs.Orig_eax)
}

func (t *tracerImpl) callback(regs syscall.PtraceRegs, exit bool) {
	// params: %ebx, %ecx, %edx, %esi, %edi, %ebp
	t.callback_generic(regs, exit)
}

func (t *tracerImpl) customDecodeArgs(trace *Trace, regs syscall.PtraceRegs) bool {
	return false
}
