package libtrace

import (
	"fmt"
	"log"
	"runtime"
	"syscall"
)

func (t *tracerImpl) Run() (err error) {

	if t.cmd.SysProcAttr == nil {
		t.cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
	} else {
		t.cmd.SysProcAttr.Ptrace = true
	}

	runtime.LockOSThread()

	if err = t.cmd.Start(); err != nil {
		return
	}

	var waitStatus syscall.WaitStatus

	if _, err = syscall.Wait4(t.cmd.Process.Pid, &waitStatus, 0, nil); err != nil {
		return
	}

	if waitStatus.Exited() {
		return
	}

	// Set options to detect our syscalls
	if err = syscall.PtraceSetOptions(t.cmd.Process.Pid, syscall.PTRACE_O_TRACESYSGOOD); err != nil {
		return
	}

	var regsEntry, regsExit syscall.PtraceRegs
	// Get first syscall
	if err = syscall.PtraceGetRegs(t.cmd.Process.Pid, &regsEntry); err != nil {
		return
	}

	var exited bool
	for {
		if exited, err = wait_for_syscall(t.cmd.Process.Pid); exited || err != nil {
			return
		}

		// Get syscall info
		if err = syscall.PtraceGetRegs(t.cmd.Process.Pid, &regsEntry); err != nil {
			return
		}

		// Enter syscall
		t.callback(regsEntry, false)

		if exited, err = wait_for_syscall(t.cmd.Process.Pid); exited || err != nil {
			return
		}

		// Get syscall returned value
		if err = syscall.PtraceGetRegs(t.cmd.Process.Pid, &regsExit); err != nil {
			return
		}
		t.callback(regsExit, true)
	}
}

func wait_for_syscall(pid int) (exited bool, err error) {
	var waitStatus syscall.WaitStatus
	for {
		// Entering a syscall
		if err = syscall.PtraceSyscall(pid, 0); err != nil {
			return
		}

		if _, err = syscall.Wait4(pid, &waitStatus, 0, nil); err != nil {
			return
		}

		// Is it for us ?
		if waitStatus.Stopped() && waitStatus.StopSignal()&0x80 == 0x80 {
			return
		}

		if waitStatus.Exited() {
			exited = true
			return
		}
	}
}

var unknownSignature Signature = Signature{
	Id:   0,
	Name: "*UKNNOWN*",
	Args: nil,
}

func (t *tracerImpl) callback_generic(regs syscall.PtraceRegs, exit bool) {

	id := getSyscallId(regs)

	trace := Trace{
		Exit: exit,
	}
	if id < SyscallId(len(syscalls)) {
		trace.Signature = syscalls[id]
	} else {
		trace.Signature = &unknownSignature
	}

	if exit {
		trace.Errno = getExitCode(regs)
		// Populate args values
		t.populateArgs(&trace, regs)
	}

	var l []TracerCb
	if !exit {
		l = t.globalCallbacksOnEnter
	} else {
		l = t.globalCallbacksOnExit
	}
	for _, cb := range l {
		cb(&trace)
	}
	var m map[string][]TracerCb
	if !exit {
		m = t.callbacksOnEnter
	} else {
		m = t.callbacksOnExit
	}

	if c, ok := m[trace.Signature.Name]; ok {
		for _, cb := range c {
			cb(&trace)
		}
	}

	var lc []chan<- *Trace
	if !exit {
		lc = t.globalChannelsOnEnter
	} else {
		lc = t.globalChannelsOnExit
	}
	for _, in := range lc {
		in <- &trace
	}
	var mc map[string][]chan<- *Trace
	if !exit {
		mc = t.channelsOnEnter
	} else {
		mc = t.channelsOnExit
	}
	if c, ok := mc[trace.Signature.Name]; ok {
		for _, in := range c {
			in <- &trace
		}
	}
}

func (t *tracerImpl) populateArgs(trace *Trace, regs syscall.PtraceRegs) {
	if len(trace.Signature.Args) == 0 {
		return
	}

	trace.Args = make([]interface{}, len(trace.Signature.Args))

	for i, arg := range trace.Signature.Args {
		trace.Args[i] = t.decodeArg(arg.Type, getParam(regs, i))
	}
}

func (t *tracerImpl) decodeArg(typ interface{}, value regParam) interface{} {
	switch typ.(type) {
	case StringC:
		return t.decodeArgStringC(value)

	case int, int8, int16,
		int32, int64, uint,
		uint8, uint16, uint32,
		uint64, float32, float64:
		return value
	default:
		return "NOTIMPL=" + fmt.Sprintf("%v", value)
	}
}

func (t *tracerImpl) decodeArgStringC(value regParam) interface{} {
	out := []byte{0}
	str := make([]byte, 0, 10)
	i := 0
	extra := false
	for {
		count, err := syscall.PtracePeekData(t.cmd.Process.Pid, uintptr(value+regParam(i)), out)
		if out[0] == 0 {
			break
		}
		if i > 32 /*strsize to display*/ {
			extra = true
			break
		}
		if err != nil {
			log.Printf("Error while reading syscal arg: %s", err)
		}
		if count != 1 {
			log.Printf("Error while reading syscall arg: count = %d (should be 1)", count)
		}
		switch {
		case out[0] == '\n':
			str = append(str, '\\', 'n')
		case out[0] == '\r':
			str = append(str, '\\', 'r')
		case out[0] == '\t':
			str = append(str, '\\', 't')
		case out[0] >= ' ' && out[0] <= '~':
			str = append(str, out[0])
		default:
			str = append(str, []byte(fmt.Sprintf("\\%d", out[0]))...)
		}

		i++
	}

	result := "\"" + string(str) + "\""
	if extra {
		result += "..."
	}

	return result

}
