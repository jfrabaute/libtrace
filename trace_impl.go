package libtrace

import "os/exec"

func NewTracer(cmd *exec.Cmd) Tracer {
	return &tracerImpl{
		cmd: cmd,
		globalCallbacksOnEnter: make([]TracerCb, 0, 1),
		globalCallbacksOnExit:  make([]TracerCb, 0, 1),
		callbacksOnEnter:       make(map[string][]TracerCb),
		callbacksOnExit:        make(map[string][]TracerCb),
		globalChannelsOnEnter:  make([]chan *Trace, 0, 1),
		globalChannelsOnExit:   make([]chan *Trace, 0, 1),
		channelsOnEnter:        make(map[string][]chan *Trace),
		channelsOnExit:         make(map[string][]chan *Trace),
	}
}

type tracerImpl struct {
	cmd *exec.Cmd

	globalCallbacksOnEnter []TracerCb
	globalCallbacksOnExit  []TracerCb
	callbacksOnEnter       map[string][]TracerCb
	callbacksOnExit        map[string][]TracerCb

	globalChannelsOnEnter []chan *Trace
	globalChannelsOnExit  []chan *Trace
	channelsOnEnter       map[string][]chan *Trace
	channelsOnExit        map[string][]chan *Trace
}

func (t *tracerImpl) RegisterCb(cb TracerCb, fnNames ...string) {
	t.RegisterCbOnEnter(cb, fnNames...)
	t.RegisterCbOnExit(cb, fnNames...)
}

func (t *tracerImpl) RegisterCbOnEnter(cb TracerCb, fnNames ...string) {
	var cbs []TracerCb
	for _, name := range fnNames {
		if cbs = t.callbacksOnEnter[name]; cbs == nil {
			cbs = make([]TracerCb, 0, 1)
		}
		cbs = append(cbs, cb)
		t.callbacksOnEnter[name] = cbs
	}
}

func (t *tracerImpl) RegisterCbOnExit(cb TracerCb, fnNames ...string) {
	var cbs []TracerCb
	for _, name := range fnNames {
		if cbs = t.callbacksOnExit[name]; cbs == nil {
			cbs = make([]TracerCb, 0, 1)
		}
		cbs = append(cbs, cb)
		t.callbacksOnExit[name] = cbs
	}
}

func (t *tracerImpl) RegisterGlobalCb(cb TracerCb) {
	t.RegisterGlobalCbOnEnter(cb)
	t.RegisterGlobalCbOnExit(cb)
}

func (t *tracerImpl) RegisterGlobalCbOnEnter(cb TracerCb) {
	t.globalCallbacksOnEnter = append(t.globalCallbacksOnEnter, cb)
}

func (t *tracerImpl) RegisterGlobalCbOnExit(cb TracerCb) {
	t.globalCallbacksOnExit = append(t.globalCallbacksOnExit, cb)
}

func (t *tracerImpl) RegisterChannel(in chan *Trace, fnNames ...string) {
	t.RegisterChannelOnEnter(in, fnNames...)
	t.RegisterChannelOnExit(in, fnNames...)
}

func (t *tracerImpl) RegisterChannelOnEnter(in chan *Trace, fnNames ...string) {
	var cbs []chan *Trace
	for _, name := range fnNames {
		if cbs = t.channelsOnEnter[name]; cbs == nil {
			cbs = make([]chan *Trace, 0, 1)
		}
		cbs = append(cbs, in)
		t.channelsOnEnter[name] = cbs
	}
}

func (t *tracerImpl) RegisterChannelOnExit(in chan *Trace, fnNames ...string) {
	var cbs []chan *Trace
	for _, name := range fnNames {
		if cbs = t.channelsOnExit[name]; cbs == nil {
			cbs = make([]chan *Trace, 0, 1)
		}
		cbs = append(cbs, in)
		t.channelsOnExit[name] = cbs
	}
}

func (t *tracerImpl) RegisterGlobalChannel(in chan *Trace) {
	t.RegisterGlobalChannelOnEnter(in)
	t.RegisterGlobalChannelOnExit(in)
}

func (t *tracerImpl) RegisterGlobalChannelOnEnter(in chan *Trace) {
	t.globalChannelsOnEnter = append(t.globalChannelsOnEnter, in)
}

func (t *tracerImpl) RegisterGlobalChannelOnExit(in chan *Trace) {
	t.globalChannelsOnExit = append(t.globalChannelsOnExit, in)
}
