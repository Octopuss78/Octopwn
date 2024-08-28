from pwn import *

ARCH = "" #CHANGE ME --> 'amd64' for ELF x64 and 'i386' for ELF x86
BINARY = "" #CHANGE ME
elf = ELF(BINARY)
rop = ROP(elf)
gadgets = rop.gadgets

_syscall = rop.syscall 
regl = []

if ARCH == "amd64":
    regl = ["pop rax", "pop rbx", "pop rcx", "pop rdx", "pop rsi", "pop rdi", "pop rsi", "pop r8", "pop r9", "pop rsp" "pop rbp"]
elif ARCH == "i386":
    regl = ["pop eax", "pop ebx", "pop ecx", "pop edx", "pop esi", "pop edi", "pop esi", "pop esp", "pop ebp"]
data_addr = elf.get_section_by_name('.data').header
data_end = hex(data_addr.sh_size + data_addr.sh_addr)

print(f"\n[*] BINARY: {BINARY}")
print(f"[*] ARCH: {ARCH}\n")

if elf.get_section_by_name('.dynamic'):
    print("[*] Dynamically linked")
    dynamic_section = elf.get_section_by_name('.dynamic')
    if dynamic_section:
        for tag, value in dynamic_section.dynstrtab.items():
            if tag == 'DT_NEEDED':
                print(value.decode())
else:
    print("[*] Statically Linked")

print("[+] SYSCALL:\n")
print(f"{hex(_syscall.address)}: {_syscall.details.insns}")
print()

print("[+] Pop Gadgets:\n")
for e in regl:
    x = rop.find_gadget([e, "ret"])
    if x:
        print(f"{hex(x.address)}: {x.insns}")


print("\n[+] Sections:\n")
print(f".data:\n   Range: {hex(data_addr.sh_addr)}-{data_end}\n   Size: {hex(data_addr.sh_size)}\n")

bin_sh = 0 
try :
    bin_sh = next(elf.search(b'/bin/sh'))
    print(f"[+] Interesting strings:\n \"/bin/sh\": {hex(bin_sh)}")
except:
    pass
