# Nimem

## Cheatsheet
```nim
type
  Process* = object
    name*: string
    pid*: int
    debug*: bool
    when defined(windows):
      handle*: HANDLE

  Module* = object
    name*: string
    base*: ByteAddress
    `end`*: ByteAddress
    size*: int

iterator enumProcesses*: Process
proc pidExists*(pid: int): bool
proc getProcessId*(procName: string): int
proc getProcessName*(pid: int): string
proc openProcess*(pid: int = 0, processName: string = "", debug: bool = false): Process
proc closeProcess*(process: Process)
proc is64bit*(process: Process): bool
iterator enumModules*(process: Process): Module
proc getModule*(process: Process, moduleName: string): Module

proc read*(process: Process, address: ByteAddress, t: typedesc): t
proc readSeq*(process: Process, address: ByteAddress, size: int, t: typedesc = byte): seq[t]
proc readString*(process: Process, address: ByteAddress, size: int = 30): string
proc write*(process: Process, address: ByteAddress, data: auto)
proc writeArray*[T](process: Process, address: ByteAddress, data: openArray[T]): int {.discardable.}

proc aobScanModule*(process: Process, moduleName, pattern: string, relative: bool = false, single: bool = true): seq[ByteAddress]
```

## Example
```nim
import
  random, strformat, 
  strutils, os,
  ../src/nimem

when defined(linux):
  import posix
else:
  import winim

when isMainModule:
  randomize()

  for p in enumProcesses():
    echo fmt"PID: {p.pid} Name: {p.name}"

  var pid: int
  when defined(linux):
    pid = getpid()
  else:
    pid = GetCurrentProcessId()

  echo fmt"Process: {getProcessName(pid)}"
  let process = openProcess(pid=pid)
  for m in enumModules(process):
    echo "\t" & fmt"Module: {m.name} Base: {m.base.toHex()}"

  var 
    myInt: int
    address = cast[ByteAddress](myInt.addr)

  echo fmt"Address of 'myInt': {address.toHex()}"

  for _ in 1..5:
    var randValue = rand(1000)
    echo fmt"writing `myInt`: {randValue}"
    process.write(address, randValue)
    sleep(500)
    echo fmt"reading `myInt`: {process.read(address, int)}"
    sleep(1500)
```