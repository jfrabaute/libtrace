package libtrace

import (
	"log"
	"syscall"
)

type SyscallId int32

type ReturnCode int32

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

func getReturnCode(regs syscall.PtraceRegs) ReturnCode {
	return ReturnCode(regs.Eax)
}

func getSyscallId(regs syscall.PtraceRegs) (SyscallId, int) {
	if regs.Orig_eax == 102 /*socketcall*/ {
		return SyscallId(regs.Ebx + 400), 1
	} else if regs.Orig_eax == 117 /* ipc */ {
		return SyscallId(regs.Ebx + 420), 1
	} else {
		return SyscallId(regs.Orig_eax), 0
	}
}

func (t *tracerImpl) callback(regs syscall.PtraceRegs, exit bool) {
	// params: %ebx, %ecx, %edx, %esi, %edi, %ebp
	t.callback_generic(regs, exit)
}

func (t *tracerImpl) customDecodeArgs(trace *Trace, regs syscall.PtraceRegs) bool {
	return true
}

var decodeReturnCodeFnMap = map[SyscallId]decodeReturnCodeFn{
	5 /*open*/ : decodeReturnCodeLinux,
}
