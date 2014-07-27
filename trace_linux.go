package libtrace

import (
	"fmt"
	"log"
	"reflect"
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
	}

	// Populate args values
	t.populateArgs(&trace, regs)

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

func (t *tracerImpl) decodeArg(typ reflect.Type, value regParam) interface{} {
	switch typ.Kind() {
	case reflect.String:
		out := []byte{0}
		str := make([]byte, 0, 10)
		i := 0
		for {
			count, err := syscall.PtracePeekData(t.cmd.Process.Pid, uintptr(value+regParam(i)), out)
			if out[0] == 0 {
				break
			}
			if err != nil {
				log.Printf("Error while reading syscal arg: %s", err)
			}
			if count != 1 {
				log.Printf("Error while reading syscall arg: count = %d (should be 1)", count)
			}
			str = append(str, out[0])
			i++
		}
		return "\"" + string(str) + "\""

	case reflect.Int, reflect.Int8, reflect.Int16,
		reflect.Int32, reflect.Int64, reflect.Uint,
		reflect.Uint8, reflect.Uint16, reflect.Uint32,
		reflect.Uint64, reflect.Float32, reflect.Float64:
		return value
	default:
		return "NOTIMPL=" + fmt.Sprintf("%v", value)
	}
}
