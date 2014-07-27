package libtrace

import "reflect"

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

type Trace struct {
	*Signature
	Args  []interface{} // Args passed in
	Errno uint64        // Result
	Exit  bool          // false when entering the syscal, true when exiting
}

type TracerCb func(trace *Trace)

type Arg struct {
	Name string
	Type reflect.Type
	// True if the arg is a ptr to the type
	Ptr bool
	// True if the arg is a const
	Const bool
}

type Signature struct {
	Id   SyscallId
	Name string
	Args []Arg
}
