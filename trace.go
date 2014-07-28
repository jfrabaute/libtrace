package libtrace

type Tracer interface {
	// Register a callback that will be called
	// in the enter phase when
	// the named syscalls will be executed
	RegisterCbOnEnter(cb TracerCb, fnNames ...string)
	// Register a callback that will be called
	// in the exit phase when
	// the named syscalls will be executed
	RegisterCbOnExit(cb TracerCb, fnNames ...string)
	// Shorcut for RegisterCbOnEnter + RegisterCbOnExit
	RegisterCb(cb TracerCb, fnNames ...string)
	// Register a callback that will be called
	// in the enter phase for all the syscalls
	RegisterGlobalCbOnEnter(cb TracerCb)
	// Register a callback that will be called
	// in the exit phase for all the syscalls
	RegisterGlobalCbOnExit(cb TracerCb)
	// Shortcut for RegisterGlobalCbOnEnter + RegisterGlobalCbOnExit
	RegisterGlobalCb(cb TracerCb)
	// Register a channel where the Trace info
	// will be sent in the enter phase
	// when the named syscalls will be executed
	RegisterChannelOnEnter(out chan<- *Trace, fnNames ...string)
	// Register a channel where the Trace info
	// will be sent in the exit phase
	// when the named syscalls will be executed
	RegisterChannelOnExit(out chan<- *Trace, fnNames ...string)
	// Shortcut for RegisterChannelOnEnter + RegisterChannelOnExit
	RegisterChannel(out chan<- *Trace, fnNames ...string)
	// Register a channel where the Trace info
	// will be sent in the enter phase
	// for all the syscalls
	RegisterGlobalChannelOnEnter(out chan<- *Trace)
	// Register a channel where the Trace info
	// will be sent in the exit phase
	// for all the syscalls
	RegisterGlobalChannelOnExit(out chan<- *Trace)
	// Shortcut for RegisterGlobalChannelOnEnter + RegisterGlobalChannelOnExit
	RegisterGlobalChannel(out chan<- *Trace)

	Run() error
}

type ArgValue struct {
	Value interface{}
	Str   string // String representation of the value
}

func (arg ArgValue) String() string {
	return arg.Str
}

type ReturnValue struct {
	Code        ReturnCode
	Description string
}

type Trace struct {
	*Signature
	Args   []ArgValue  // Args passed in
	Return ReturnValue // Result
	Exit   bool        // false when entering the syscal, true when exiting
}

type TracerCb func(trace *Trace)

type Arg struct {
	Name string
	Type interface{} // Zero value of the type, so we can use type switch to decode it
	// True if the arg is a const
	Const bool
}

type Signature struct {
	Id   SyscallId
	Name string
	Args []Arg
}

// Custom types
type StringC string      // String arg passed as C String (null terminated)
type StringBuffer string // String arg passed with a "count" value
type Buffer []byte
