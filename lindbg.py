#!/usr/bin/env python3

"""A linux clone of windbg.

lindbg is a remote debugger client that presents a user-interface similar to
windbg. This client communicates with `ldbserver`, which hosts the debuggee. In
it's current form, lindbg implements a small subset of windbg commands and
supports linux x86_64 executables.

To debug a target, run `ldbserver <target-cmd-line>`, followed by
`./lindbg.py`.
"""

import argparse
import base64
import cmd
import json
import os
import textwrap
import socket
import string
import struct

import binascii
import capstone

STRING_PRINTABLE = string.digits + string.ascii_letters + string.punctuation + " "
BYTES_PRINTABLE = STRING_PRINTABLE.encode("ascii")
AMD64_MAX_INSTR_SIZE = 15

INTRO_TEXT_FMT = textwrap.dedent("""\

    Taco (R) Linux Debugger Version 0.1.0 AMD64
    Copyright (c) Taco Corporation. All rights reserved.

    CommandLine: {:s}

    ************* Symbol Path validation summary *************
    Response                         Time (ms)     Location
    Deferred                                       srv*C:\\symbols*https://msdl.microsoft.com/download/symbols
    Symbol search path is: srv*C:\\symbols*https://msdl.microsoft.com/download/symbols
    Executable search path is:
    """)


class RemoteTarget(object):

    CMD_GET_COMMANDLINE  = 1
    CMD_GET_MODULES      = 2
    CMD_GET_REGISTERS    = 3
    CMD_SET_REGISTERS    = 4
    CMD_GET_BYTES        = 5
    CMD_SET_BYTES        = 6
    CMD_GO               = 7
    CMD_STEP_INSTRUCTION = 8

    def __init__(self, sock):
        self.s = sock

    def _sendjson(self, json_data):
        json_str = json.dumps(json_data)
        msg = struct.pack("!I", len(json_str)) + json_str.encode("utf-8")
        self.s.sendall(msg)

    def _recvjson(self):
        sz_str = self.s.recv(4)
        if len(sz_str) != 4:
            return None

        sz = struct.unpack("!I", sz_str)[0]
        data = b""
        while len(data) < sz:
            buf = self.s.recv(sz - len(data))
            if not buf:
                return None
            data += buf
        data = data.decode("utf-8")

        try:
            json_obj = json.loads(data)
        except json.JSONDecodeError:
            json_obj = None

        return json_obj

    @property
    def commandline(self):
        params = {"command": RemoteTarget.CMD_GET_COMMANDLINE}
        self._sendjson(params)

        response = self._recvjson()
        if (response is None or "status" not in response or
                response["status"] != 0 or "commandline" not in response):
            return ""

        # quote arguments containing whitespace before returning the commandline
        argv = base64.b64decode(response["commandline"]).decode("utf-8")
        argv = argv.split("\0")
        for i in range(len(argv)):
            if any(c in argv[i] for c in string.whitespace):
                argv[i] = '"{:s}"'.format(argv[i])

        return " ".join(argv)

    @property
    def modules(self):
        params = {"command": RemoteTarget.CMD_GET_MODULES}
        self._sendjson(params)

        response = self._recvjson()
        if (response is None or "status" not in response or
                response["status"] != 0 or "modules" not in response):
            return []

        # convert module start and end addresses to ints
        for module in response["modules"]:
            module["start"] = int(module["start"], 16)
            module["end"] = int(module["end"], 16)

        return response["modules"]

    def get_registers(self):
        params = {"command": RemoteTarget.CMD_GET_REGISTERS}
        self._sendjson(params)

        response = self._recvjson()
        if (response is None or "status" not in response or
                response["status"] != 0 or "registers" not in response):
            return {}

        return response["registers"]

    def set_registers(self, registers):
        params = {"command": RemoteTarget.CMD_SET_REGISTERS,
                  "registers": registers}
        self._sendjson(params)

        response = self._recvjson()
        if (response is None or "status" not in response or
                response["status"] != 0):
            return False

        return True

    def get_bytes(self, address, size):
        params = {"command": RemoteTarget.CMD_GET_BYTES,
                  "address": address,
                  "size": size}
        self._sendjson(params)

        response = self._recvjson()
        if (response is None or "status" not in response or
                response["status"] != 0 or "bytes" not in response):
            return b""

        return base64.b64decode(response["bytes"])

    def set_bytes(self, address, data):
        params = {"command": RemoteTarget.CMD_SET_BYTES,
                  "address": address,
                  "data": base64.b64encode(data).decode("ascii")}
        self._sendjson(params)

        response = self._recvjson()
        if response is None or response["status"] != 0:
            return False

        return True

    def go(self):
        params = {"command": RemoteTarget.CMD_GO}
        self._sendjson(params)

        response = self._recvjson()
        if (response is None or "status" not in response or
                response["status"] != 0 or "stopval" not in response or
                "exited" not in response):
            return True, -1

        return response["exited"], response["stopval"]

    def step_instruction(self):
        params = {"command": RemoteTarget.CMD_STEP_INSTRUCTION}
        self._sendjson(params)

        response = self._recvjson()
        if (response is None or "status" not in response or
                response["status"] != 0 or "stopval" not in response or
                "exited" not in response):
            return True, -1

        return response["exited"], response["stopval"]

    def close(self):
        try:
            self.s.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.s.close()


class Breakpoint(object):

    def __init__(self, target, address):
        self._target = target
        self._address = address
        self._enabled = False
        self._orig_byte = b""

    @property
    def address(self):
        return self._address

    @property
    def enabled(self):
        return self._enabled

    def enable(self):
        self._enabled = True

    def disable(self):
        self._enabled = False

    def insert(self):
        self._orig_byte = self._target.get_bytes(self._address, 1)
        if len(self._orig_byte) != 1:
            return False
        self._target.set_bytes(self._address, b"\xcc")

    def remove(self):
        assert len(self._orig_byte) == 1
        success = self._target.set_bytes(self._address, self._orig_byte)
        if success:
            self._orig_byte = b""


class RdbShell(cmd.Cmd):

    def __init__(self, target):
        super().__init__()
        self._target = target
        self._breakpoints = []
        self.prompt = "0:000> "

    def _insert_breakpoints(self):
        """Helper function to insert all enabled breakpoints into the target."""
        for bp in self._breakpoints:
            if bp and bp.enabled:
                bp.insert()

    def _remove_breakpoints(self):
        """Helper function to remove all enabled breakpoints from the target."""
        for bp in self._breakpoints:
            if bp and bp.enabled:
                bp.remove()

    def _breakpoint_exists(self, address):
        """Helper function to determine if an enabled breakpoint exists at the given address."""
        for bp in self._breakpoints:
            if bp and bp.enabled and bp.address == address:
                return True
        return False

    def _resume_target(self):
        """Helper function to resume execution of the target.

        This function handles breakpoints properly by inserting and removing them
        as necessary. Additionally, it will fix up RIP if a breakpoint stops execution.
        """
        # if we're stopped on a breakpoint, we need to single-step past it before
        # continuing execution.
        regs = self._target.get_registers()
        if self._breakpoint_exists(regs["rip"]):
            exited, stopval = self._target.step_instruction()
            if exited:
                return exited, stopval

            # if this instruction is also a breakpoint, we're done
            regs = self._target.get_registers()
            if self._breakpoint_exists(regs["rip"]):
                return exited, stopval

        # insert all breakpoints and continue
        self._insert_breakpoints()
        exited, stopval = self._target.go()
        self._remove_breakpoints()
        if exited:
            return exited, stopval

        # if we stopped due to a breakpoint, we need to reset RIP to RIP - 1
        regs = self._target.get_registers()
        if self._breakpoint_exists(regs["rip"] - 1):
            regs["rip"] -= 1
            self._target.set_registers(regs)

        return exited, stopval

    def cmdloop(self, intro=""):
        """Override cmdloop to provide a custom intro."""
        intro = INTRO_TEXT_FMT.format(self._target.commandline)
        for module in self._target.modules:
            line = "ModLoad: {:08x}`{:08x} {:08x}`{:08x}   {:s}\n"
            intro += line.format(module["start"] >> 32, module["start"] & 0xffffffff,
                                 module["end"] >> 32, module["end"] & 0xffffffff,
                                 module["name"])

        super().cmdloop(intro=intro)

    def do_q(self, arg):
        """The q command ends the debugging session."""
        self._target.close()
        return True

    def do_shell(self, arg):
        """The ! command runs a shell command on the local host."""
        os.system(arg)

    def do_lm(self, arg):
        """The lm command displays loaded modules."""
        print("start             end                 module name")
        for module in self._target.modules:
            if "/" in module["name"]:
                module["name"] = module["name"].split("/")[-1]
            line = "{:08x}`{:08x} {:08x}`{:08x}   {:s}   (deferred)"
            line = line.format(module["start"] >> 32, module["start"] & 0xffffffff,
                               module["end"] >> 32, module["end"] & 0xffffffff,
                               module["name"])
            print(line)

    def do_r(self, arg):
        """The r command displays registers."""
        regs = self._target.get_registers()
        if arg:
            if arg in regs:
                print("{:s}={:016x}".format(arg, regs[arg]))
            else:
                print("         ^ Bad register error in 'r {:s}'".format(arg))
        else:
            print("rax={:016x} rbx={:016x} rcx={:016x}".format(regs["rax"], regs["rbx"], regs["rcx"]))
            print("rdx={:016x} rsi={:016x} rdi={:016x}".format(regs["rdx"], regs["rsi"], regs["rdi"]))
            print("rip={:016x} rsp={:016x} rbp={:016x}".format(regs["rip"], regs["rsp"], regs["rbp"]))
            print(" r8={:016x}  r9={:016x} r10={:016x}".format(regs["r8"], regs["r9"], regs["r10"]))
            print("r11={:016x} r12={:016x} r13={:016x}".format(regs["r11"], regs["r12"], regs["r13"]))
            print("r14={:016x} r15={:016x}".format(regs["r14"], regs["r15"]))
            print("iopl=0         <screw these EFLAGS values>")
            line = "cs={:04x}  ss={:04x}  ds={:04x}  es={:04x}  fs={:04x}  gs={:04x}             efl={:08x}"
            print(line.format(regs["cs"], regs["ss"], regs["ds"], regs["es"],
                              regs["fs"], regs["gs"], regs["eflags"]))

    def do_da(self, arg):
        """Display ASCII characters."""
        try:
            address = int(arg, 16)
        except ValueError:
            print("Couldn't resolve error at '{:s}'".format(arg))
            return

        # receive data until a NULL terminator
        data = b""
        while True:
            data += self._target.get_bytes(address, 128)
            if b"\0" in data:
                data = data[:data.index(b"\0")]
                break

        # replace non-printable bytes and print the string in 32-byte lines
        data = "".join(chr(b) if b in BYTES_PRINTABLE else "." for b in data)
        for i in range(0, len(data), 32):
            chunk_address = address + i
            chunk_ascii = data[i:i+32]
            line = "{:08x}`{:08x}  \"{:s}\""
            print(line.format(chunk_address >> 32, chunk_address & 0xffffffff,
                              chunk_ascii))

    def do_db(self, arg):
        """Display byte values and ASCII characters."""
        try:
            address = int(arg, 16)
        except ValueError:
            print("Couldn't resolve error at '{:s}'".format(arg))
            return

        data = self._target.get_bytes(address, 128)

        # print hexdump of data in 16-byte lines
        for i in range(0, 128, 16):
            chunk_address = address + i
            chunk_bytes = ["{:02x}".format(b) for b in data[i:i+16]]
            chunk_ascii = [chr(b) if b in BYTES_PRINTABLE else "." for b in data[i:i+16]]
            line = "{:08x}`{:08x}  {:s}-{:s}  {:s}"
            print(line.format(chunk_address >> 32, chunk_address & 0xffffffff,
                              " ".join(chunk_bytes[:8]), " ".join(chunk_bytes[8:]),
                              "".join(chunk_ascii)))

    def do_dw(self, arg):
        """Display word values (2 bytes)."""
        try:
            address = int(arg, 16)
        except ValueError:
            print("Couldn't resolve error at '{:s}'".format(arg))
            return

        data = self._target.get_bytes(address, 128)

        # print hexdump of data in 16-byte lines
        for i in range(0, 128, 16):
            chunk_address = address + i
            chunk = data[i:i+16]
            chunk_words = []
            for j in range(0, 16, 2):
                chunk_words.append(struct.unpack("<H", chunk[j:j+2])[0])
            chunk_words = ["{:04x}".format(w) for w in chunk_words]
            line = "{:08x}`{:08x}  {:s}"
            print(line.format(chunk_address >> 32, chunk_address & 0xffffffff,
                              " ".join(chunk_words)))

    def do_dd(self, arg):
        """Display double-word values (4 bytes)."""
        try:
            address = int(arg, 16)
        except ValueError:
            print("Couldn't resolve error at '{:s}'".format(arg))
            return

        data = self._target.get_bytes(address, 128)

        # print hexdump of data in 16-byte lines
        for i in range(0, 128, 16):
            chunk_address = address + i
            chunk = data[i:i+16]
            chunk_dwords = []
            for j in range(0, 16, 4):
                chunk_dwords.append(struct.unpack("<I", chunk[j:j+4])[0])
            chunk_dwords = ["{:08x}".format(d) for d in chunk_dwords]
            line = "{:08x}`{:08x}  {:s}"
            print(line.format(chunk_address >> 32, chunk_address & 0xffffffff,
                              " ".join(chunk_dwords)))

    def do_dq(self, arg):
        """Display quad-word values (8 bytes)."""
        try:
            address = int(arg, 16)
        except ValueError:
            print("Couldn't resolve error at '{:s}'".format(arg))
            return

        data = self._target.get_bytes(address, 128)

        # print hexdump of data in 16-byte lines
        for i in range(0, 128, 16):
            chunk_address = address + i
            chunk = data[i:i+16]
            chunk_qwords = []
            for j in range(0, 16, 8):
                chunk_qwords.append(struct.unpack("<Q", chunk[j:j+8])[0])
            chunk_qwords = ["{:08x}`{:08x}".format(q >> 32, q & 0xffffffff) for q in chunk_qwords]
            line = "{:08x}`{:08x}  {:s}"
            print(line.format(chunk_address >> 32, chunk_address & 0xffffffff,
                              " ".join(chunk_qwords)))

    def do_u(self, arg):
        """The u command displays an assembly translation of the specified program code in memory."""
        if arg:
            try:
                address = int(arg, 16)
            except ValueError:
                print("Couldn't resolve error at '{:s}'".format(arg))
                return
        else:
            address = self._target.get_registers()["rip"]

        code = self._target.get_bytes(address, AMD64_MAX_INSTR_SIZE * 8)

        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        for inst in list(md.disasm(code, address))[:8]:
            inst_bytes = binascii.hexlify(inst.bytes).decode("ascii")
            line = "{:08x}`{:08x} {:16s}{:8s}{:s}"
            print(line.format(inst.address >> 32, inst.address & 0xffffffff,
                              inst_bytes, inst.mnemonic, inst.op_str))

    def do_bp(self, arg):
        """The bp command sets a software breakpoint."""
        try:
            address = int(arg, 16)
        except ValueError:
            print("Couldn't resolve error at '{:s}'".format(arg))
            return

        # check for existing breakpoints with this address
        for i, bp in enumerate(self._breakpoints):
            if bp.address == address:
                print("breakpoint {:d} redefined".format(i))
                bp.enable()
                return

        # no previous breakpoint found for this address - create a new one
        new_bp = Breakpoint(self._target, address)
        new_bp.enable()

        # insert the breakpoint if there's a slot, otherwise append to the list
        for i, bp in enumerate(self._breakpoints):
            if bp is None:
                self._breakpoints[i] = new_bp
                return
        self._breakpoints.append(new_bp)

    def do_be(self, arg):
        """The be command restores one or more breakpoints that were previously disabled."""
        if arg:
            try:
                idx = int(arg, 16)
            except ValueError:
                print("         ^ Syntax error in '{:s}'".format(arg))
                return
            if 0 <= idx < len(self._breakpoints) and self._breakpoints[idx]:
                self._breakpoints[idx].enable()
        else:
            # enable all breakpoints
            for bp in self._breakpoints:
                if bp:
                    bp.enable()

    def do_bd(self, arg):
        """The bd command disables, but does not delete, previously set breakpoints."""
        if arg:
            try:
                idx = int(arg, 16)
            except ValueError:
                print("         ^ Syntax error in '{:s}'".format(arg))
                return
            if 0 <= idx < len(self._breakpoints) and self._breakpoints[idx]:
                self._breakpoints[idx].disable()
        else:
            # disable all breakpoints
            for bp in self._breakpoints:
                if bp:
                    bp.disable()

    def do_bc(self, arg):
        """The bc command permanently removes previously set breakpoints from the system."""
        if arg:
            try:
                idx = int(arg, 16)
            except ValueError:
                print("         ^ Syntax error in '{:s}'".format(arg))
                return
            if 0 <= idx < len(self._breakpoints) and self._breakpoints[idx]:
                self._breakpoints[idx] = None
        else:
            # clear all breakpoints
            for i in range(len(self._breakpoints)):
                self._breakpoints[i] = None

    def do_bl(self, arg):
        """The bl command lists information about existing breakpoints."""
        for i, bp in enumerate(self._breakpoints):
            if bp:
                enabled = "e" if bp.enabled else "d"
                line = "{:6d} {:s} Disable Clear  {:08x}`{:08x}     0001 (0001)  0:****"
                print(line.format(i, enabled, bp.address >> 32, bp.address & 0xffffffff))

    def do_p(self, arg):
        """The p command executes a single instruction. When subroutine calls occur, they are treated as a single step."""
        # check to see if the current instruction is a call
        address = self._target.get_registers()["rip"]
        code = self._target.get_bytes(address, AMD64_MAX_INSTR_SIZE)
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        inst = next(md.disasm(code, address))

        if inst.mnemonic == "call":
            if self._breakpoint_exists(inst.address + inst.size):
                exited, stopval = self._resume_target()
            else:
                bp = Breakpoint(self._target, inst.address + inst.size)
                bp.enable()
                self._breakpoints.append(bp)
                exited, stopval = self._resume_target()
                self._breakpoints.remove(bp)
        else:
            exited, stopval = self._target.step_instruction()

        if exited:
            print("[+] Target exited with value: {:d}".format(stopval))

    def do_t(self, arg):
        """The t command executes a single instruction. When subroutine calls occur, each of their steps is also traced."""
        exited, stopval = self._target.step_instruction()
        if exited:
            print("[+] Target exited with value: {:d}".format(stopval))

    def do_g(self, arg):
        """The g command starts executing the given process or thread."""
        exited, stopval = self._resume_target()
        if exited:
            print("[+] Target exited with value: {:d}".format(stopval))


def run_debug_session(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))

    target = RemoteTarget(s)
    session = RdbShell(target)
    session.cmdloop()


def main():
    parser = argparse.ArgumentParser(description="Start a remote debugging session")
    parser.add_argument("-i", "--ip", default="localhost",
                        help="IP to listen on")
    parser.add_argument("-p", "--port", default=4242,
                        help="Port to listen on")

    args = parser.parse_args()

    run_debug_session(args.ip, args.port)


if __name__ == "__main__":
    main()
