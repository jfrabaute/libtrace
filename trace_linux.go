package libtrace

import (
	"encoding/binary"
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

type decodeReturnCodeFn func(trace *Trace)

func (t *tracerImpl) callback_generic(regs syscall.PtraceRegs, exit bool) {

	id := getSyscallId(regs)

	trace := Trace{
		Exit: exit,
	}
	if id < SyscallId(len(syscalls)) {
		trace.Signature = syscalls[id]
		if trace.Signature == &unknownSignature {
			trace.Signature = &Signature{}
			*trace.Signature = unknownSignature
			trace.Signature.Id = id
			trace.Signature.Name = fmt.Sprintf("*UNKNOWN(%d)*", id)
		}
	} else {
		trace.Signature = &Signature{}
		*trace.Signature = unknownSignature
		trace.Signature.Id = id
		trace.Signature.Name = fmt.Sprintf("*UNKNOWN(%d)*", id)
	}

	if exit {
		trace.Return.Code = getReturnCode(regs)
		t.decodeReturnCode(&trace)
		// Populate args values
		t.decodeArgs(&trace, regs)
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

func (t *tracerImpl) decodeReturnCode(trace *Trace) {
	if fn, ok := decodeReturnCodeFnMap[trace.Id]; ok {
		fn(trace)
	}
}

func (t *tracerImpl) decodeArgs(trace *Trace, regs syscall.PtraceRegs) {
	if trace.Signature.Args == nil {
		trace.Args = []ArgValue{
			ArgValue{Str: "*ARGSNOTDEFINED*"},
		}
		return
	}
	if len(trace.Signature.Args) == 0 {
		return
	}

	trace.Args = make([]ArgValue, len(trace.Signature.Args))

	defaultDecode := t.customDecodeArgs(trace, regs)

	if defaultDecode {
		for i, arg := range trace.Signature.Args {
			t.decodeArg(arg.Type, getParam(regs, i), &trace.Args[i])
		}
	}
}

func (t *tracerImpl) decodeArg(typ interface{}, value regParam, argValue *ArgValue) {
	switch typ.(type) {
	case StringC:
		argValue.Str = t.decodeArgStringC(value)
		argValue.Value = argValue.Str

	case int, int8, int16,
		int32, int64, uint,
		uint8, uint16, uint32,
		uint64, float32, float64:
		argValue.Value = value
		argValue.Str = fmt.Sprintf("%d", argValue.Value)
	case *uint64:
		var out []byte = make([]byte, 8)
		count, err := syscall.PtracePeekData(t.cmd.Process.Pid, uintptr(value), out)
		if err != nil {
			log.Printf("Error while reading syscall arg: %s", err)
		}
		if count != 8 {
			log.Printf("Error while reading syscall arg: count = %d (should be 8)", count)
		}
		argValue.Value = binary.LittleEndian.Uint64(out)
		argValue.Str = fmt.Sprintf("%d", argValue.Value)
	default:
		argValue.Value = value
		argValue.Str = fmt.Sprintf("%v", value) + "(NOTIMPL=" + reflect.TypeOf(typ).String() + ")"
	}
}

func (t *tracerImpl) decodeArgStringC(value regParam) string {
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
			log.Printf("Error while reading syscall arg: %s", err)
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

func decodeReturnCodeLinux(trace *Trace) {
	if trace.Return.Code < 0 {
		if d, ok := linuxReturnCodes[-int(trace.Return.Code)]; ok {
			trace.Return.Description = d
		}
	}
}

var linuxReturnCodes = map[int]string{
	1:   "EPERM (Operation not permitted)",
	2:   "ENOENT (No such file or directory)",
	3:   "ESRCH (No such process)",
	4:   "EINTR (Interrupted system call)",
	5:   "EIO (I/O error)",
	6:   "ENXIO (No such device or address)",
	7:   "E2BIG (Arg list too long)",
	8:   "ENOEXEC (Exec format error)",
	9:   "EBADF (Bad file number)",
	10:  "ECHILD (No child processes)",
	11:  "EAGAIN (Try again)",
	12:  "ENOMEM (Out of memory)",
	13:  "EACCES (Permission denied)",
	14:  "EFAULT (Bad address)",
	15:  "ENOTBLK (Block device required)",
	16:  "EBUSY (Device or resource busy)",
	17:  "EEXIST (File exists)",
	18:  "EXDEV (Cross-device link)",
	19:  "ENODEV (No such device)",
	20:  "ENOTDIR (Not a directory)",
	21:  "EISDIR (Is a directory)",
	22:  "EINVAL (Invalid argument)",
	23:  "ENFILE (File table overflow)",
	24:  "EMFILE (Too many open files)",
	25:  "ENOTTY (Not a typewriter)",
	26:  "ETXTBSY (Text file busy)",
	27:  "EFBIG (File too large)",
	28:  "ENOSPC (No space left on device)",
	29:  "ESPIPE (Illegal seek)",
	30:  "EROFS (Read-only file system)",
	31:  "EMLINK (Too many links)",
	32:  "EPIPE (Broken pipe)",
	33:  "EDOM (Math argument out of domain of func)",
	34:  "ERANGE (Math result not representable)",
	35:  "EDEADLK (Resource deadlock would occur)",
	36:  "ENAMETOOLONG (File name too long)",
	37:  "ENOLCK (No record locks available)",
	38:  "ENOSYS (Function not implemented)",
	39:  "ENOTEMPTY (Directory not empty)",
	40:  "ELOOP (Too many symbolic links encountered)",
	42:  "ENOMSG (No message of desired type)",
	43:  "EIDRM (Identifier removed)",
	44:  "ECHRNG (Channel number out of range)",
	45:  "EL2NSYNC (Level 2 not synchronized)",
	46:  "EL3HLT (Level 3 halted)",
	47:  "EL3RST (Level 3 reset)",
	48:  "ELNRNG (Link number out of range)",
	49:  "EUNATCH (Protocol driver not attached)",
	50:  "ENOCSI (No CSI structure available)",
	51:  "EL2HLT (Level 2 halted)",
	52:  "EBADE (Invalid exchange)",
	53:  "EBADR (Invalid request descriptor)",
	54:  "EXFULL (Exchange full)",
	55:  "ENOANO (No anode)",
	56:  "EBADRQC (Invalid request code)",
	57:  "EBADSLT (Invalid slot)",
	59:  "EBFONT (Bad font file format)",
	60:  "ENOSTR (Device not a stream)",
	61:  "ENODATA (No data available)",
	62:  "ETIME (Timer expired)",
	63:  "ENOSR (Out of streams resources)",
	64:  "ENONET (Machine is not on the network)",
	65:  "ENOPKG (Package not installed)",
	66:  "EREMOTE (Object is remote)",
	67:  "ENOLINK (Link has been severed)",
	68:  "EADV (Advertise error)",
	69:  "ESRMNT (Srmount error)",
	70:  "ECOMM (Communication error on send)",
	71:  "EPROTO (Protocol error)",
	72:  "EMULTIHOP (Multihop attempted)",
	73:  "EDOTDOT (RFS specific error)",
	74:  "EBADMSG (Not a data message)",
	75:  "EOVERFLOW (Value too large for defined data type)",
	76:  "ENOTUNIQ (Name not unique on network)",
	77:  "EBADFD (File descriptor in bad state)",
	78:  "EREMCHG (Remote address changed)",
	79:  "ELIBACC (Can not access a needed shared library)",
	80:  "ELIBBAD (Accessing a corrupted shared library)",
	81:  "ELIBSCN (.lib section in a.out corrupted)",
	82:  "ELIBMAX (Attempting to link in too many shared libraries)",
	83:  "ELIBEXEC (Cannot exec a shared library directly)",
	84:  "EILSEQ (Illegal byte sequence)",
	85:  "ERESTART (Interrupted system call should be restarted)",
	86:  "ESTRPIPE (Streams pipe error)",
	87:  "EUSERS (Too many users)",
	88:  "ENOTSOCK (Socket operation on non-socket)",
	89:  "EDESTADDRREQ (Destination address required)",
	90:  "EMSGSIZE (Message too long)",
	91:  "EPROTOTYPE (Protocol wrong type for socket)",
	92:  "ENOPROTOOPT (Protocol not available)",
	93:  "EPROTONOSUPPORT (Protocol not supported)",
	94:  "ESOCKTNOSUPPORT (Socket type not supported)",
	95:  "EOPNOTSUPP (Operation not supported on transport endpoint)",
	96:  "EPFNOSUPPORT (Protocol family not supported)",
	97:  "EAFNOSUPPORT (Address family not supported by protocol)",
	98:  "EADDRINUSE (Address already in use)",
	99:  "EADDRNOTAVAIL (Cannot assign requested address)",
	100: "ENETDOWN (Network is down)",
	101: "ENETUNREACH (Network is unreachable)",
	102: "ENETRESET (Network dropped connection because of reset)",
	103: "ECONNABORTED (Software caused connection abort)",
	104: "ECONNRESET (Connection reset by peer)",
	105: "ENOBUFS (No buffer space available)",
	106: "EISCONN (Transport endpoint is already connected)",
	107: "ENOTCONN (Transport endpoint is not connected)",
	108: "ESHUTDOWN (Cannot send after transport endpoint shutdown)",
	109: "ETOOMANYREFS (Too many references: cannot splice)",
	110: "ETIMEDOUT (Connection timed out)",
	111: "ECONNREFUSED (Connection refused)",
	112: "EHOSTDOWN (Host is down)",
	113: "EHOSTUNREACH (No route to host)",
	114: "EALREADY (Operation already in progress)",
	115: "EINPROGRESS (Operation now in progress)",
	116: "ESTALE (Stale NFS file handle)",
	117: "EUCLEAN (Structure needs cleaning)",
	118: "ENOTNAM (Not a XENIX named type file)",
	119: "ENAVAIL (No XENIX semaphores available)",
	120: "EISNAM (Is a named type file)",
	121: "EREMOTEIO (Remote I/O error)",
	122: "EDQUOT (Quota exceeded)",

	123: "ENOMEDIUM (No medium found)",
	124: "EMEDIUMTYPE (Wrong medium type)",
}
