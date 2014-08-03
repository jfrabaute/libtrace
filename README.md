libtrace
========
A syscall trace library in go.

![License](http://img.shields.io/badge/license-MIT-blue.svg)

Supported Platforms
===================

* Linux
  * x86
  * x86_64

Usage
============

```go
import "github.com/jfrabaute/libtrace"
```

Create a new TracerClient and install either callbacks or channels to receive all the syscalls you want to monitor.


### Monitoring all the syscalls
```go
tracer := libtrace.NewTracer(cmd)
tracer.RegisterGlobalCbOnExit(func(trace *libtrace.Trace) {
	log.Printf("Syscall: %s\n", trace.Signature.Name)
})

tracer.Run()
```

### Monitoring only "open" syscall
```go
tracer := libtrace.NewTracer(cmd)
tracer.RegisterCbOnExit(func(trace *libtrace.Trace, "open") {
	log.Printf("open: %d %s\n", trace.Return.Code, trace.Return.Description)
})

tracer.Run()
```

Sample app:

* [gotrace](https://github.com/jfrabaute/gotrace) is a basic "strace" app written in go using "libtrace".

Licensing
=========
libtrace is licensed under the MIT License. See LICENSE for full license text.
