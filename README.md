# lindbg

`lindbg` is a linux clone of windbg.

Have you ever wanted to experience the glory of windbg on the linux command
line?

Well now you can! `lindbg` is a remote debugger client that presents a
user interface similar to that of windbg. It communicates with `ldbserver`,
which hosts a debuggee. `lindbg` implements a small subset of windbg commands
and supports linux x64 executables.

## Building

There are a few dependencies that must be installed prior to building
`ldbserver`. These can be installed with pip and your distro's package manager.

    sudo apt install libjansson-dev libb64-dev
    sudo -H pip3 install capstone

Once dependencies are installed, `ldbserver` can be compiled with `make`.

    make

## Debugging an executable

To debug an executable, pass the target process command line to `ldbserver`.
`ldbserver` will listen on the specified IP and port for a client connection
before spawning the target process.

    ./ldbserver --ip 0.0.0.0 ./test arg1 arg2 ...

Connect to the server with the client to spawn a debug session. Once connected,
you can interact with the target as if it were a local windbg session.

    $ ./lindbg.py

    TwelveTacos (R) Linux Debugger Version 0.1.0 AMD64
    Copyright (c) Taco Corporation. All rights reserved.

    CommandLine: ./test arg1 arg2 arg3

    ************* Symbol Path validation summary *************
    Response                         Time (ms)     Location
    Deferred                                       srv*C:\symbols*https://msdl.microsoft.com/download/symbols
    Symbol search path is: srv*C:\symbols*https://msdl.microsoft.com/download/symbols
    Executable search path is:
    ModLoad: 00000000`00400000 00000000`00602000   /home/user/lindbg/test
    ModLoad: 00007fa4`06c25000 00007fa4`06e4c000   /lib/x86_64-linux-gnu/ld-2.23.so

    0:000> u
    00007fa4`06c25c30 4889e7          mov     rdi, rsp
    00007fa4`06c25c33 e8780d0000      call    0x7fa406c269b0
    00007fa4`06c25c38 4989c4          mov     r12, rax
    00007fa4`06c25c3b 8b0537502200    mov     eax, dword ptr [rip + 0x225037]
    00007fa4`06c25c41 5a              pop     rdx
    00007fa4`06c25c42 488d24c4        lea     rsp, [rsp + rax*8]
    00007fa4`06c25c46 29c2            sub     edx, eax
    00007fa4`06c25c48 52              push    rdx
    0:000> t
    ld-2.23+0xc33:
    00007fa4`06c25c33 e8780d0000      call    0x7fa406c269b0
    0:000> p
    ld-2.23+0xc38:
    00007fa4`06c25c38 4989c4          mov     r12, rax
    0:000> bp 00007fa4`06c25c41
    0:000> bp 00007fa4`06c25c46
    0:000> bl
         0 e Disable Clear  00007fa4`06c25c41     0001 (0001)  0:****
         1 e Disable Clear  00007fa4`06c25c46     0001 (0001)  0:****
    0:000> g
    ld-2.23+0xc41:
    00007fa4`06c25c41 5a              pop     rdx
    0:000> r
    rax=0000000000000000 rbx=0000000000000000 rcx=00007fa406c40537
    rdx=000793e500000000 rsi=00000000000284bb rdi=00007fa406e21000
    rip=00007fa406c25c41 rsp=00007ffe7621a2f0 rbp=0000000000000000
     r8=0000000000000000  r9=00007fa406e20000 r10=00007fa406e4b030
    r11=0000000000000206 r12=0000000000400430 r13=0000000000000000
    r14=0000000000000000 r15=0000000000000000
    iopl=0         <screw these EFLAGS values>
    cs=0033  ss=002b  ds=0000  es=0000  fs=0000  gs=0000             efl=00000206
    0:000> db 00007ffe7621a2f0
    00007ffe`7621a2f0  04 00 00 00 00 00 00 00-2f c4 21 76 fe 7f 00 00  ......../.!v....
    00007ffe`7621a300  36 c4 21 76 fe 7f 00 00-3b c4 21 76 fe 7f 00 00  6.!v....;.!v....
    00007ffe`7621a310  40 c4 21 76 fe 7f 00 00-00 00 00 00 00 00 00 00  @.!v............
    00007ffe`7621a320  45 c4 21 76 fe 7f 00 00-50 c4 21 76 fe 7f 00 00  E.!v....P.!v....
    00007ffe`7621a330  63 c4 21 76 fe 7f 00 00-75 c4 21 76 fe 7f 00 00  c.!v....u.!v....
    00007ffe`7621a340  c0 c4 21 76 fe 7f 00 00-f0 c4 21 76 fe 7f 00 00  ..!v......!v....
    00007ffe`7621a350  fb c4 21 76 fe 7f 00 00-0b c5 21 76 fe 7f 00 00  ..!v......!v....
    00007ffe`7621a360  2e c5 21 76 fe 7f 00 00-38 c5 21 76 fe 7f 00 00  ..!v....8.!v....
    0:000> bc 0
    0:000> bd 1
    0:000> bl
         1 d Disable Clear  00007fa4`06c25c46     0001 (0001)  0:****
    0:000> g
    [+] Target exited with value: 0
    0:000> q
    $

## Future work

There are a great number of windbg features not supported by `lindbg`. In
addition to missing commands, many of the existing commands are not fully
implmented. Some of the bigger missing features are listed here.

- Masm evaluator for expressions
- Symbol resolution for identifiers in masm expressions
- `@<reg>` syntax for registers
- Commands to set target memory (`eb`, `ew`, `ed`, `eq`)
- Commands to set target registers (`r @eax=<val>`)
- Support for properly handling signals other than SIGTRAP in the client.
  Similarly, lindbg is missing functionality to properly continue when signals
  are received.

Furthermore, there a few areas for better error handling. In most cases, this
handling was omitted in order to build a prototype quickly.

- ldbserver: No error checks when building json objects.
- lindbg.py: Most LindbgShell command handlers assume the target program is
  still active and do not behave well if it has terminated.
- lindbg.py: Most LindbgShell command handlers don't check to see if
  RemoteTarget calls succeeded before attempting to process data.
