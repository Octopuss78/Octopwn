#!/usr/bin/python3

from pwn import *
import argparse
from colorama import Fore, Style, init

init(autoreset=True)


#TODO:
# option to show imported methods
# basic mode and detailed mode
# show permissions of sections
# improve gadgets finding (try to use ropgadget)
# add colors to printed text


def list_libs(b):
    print(f"{Fore.CYAN}[+] Linked Libraries:{Style.RESET_ALL}")
    for lib in b.get_section_by_name('.dynamic'):
        if lib['d_tag'] == 'DT_NEEDED':
            print(f"{Fore.GREEN}- {lib['d_val']}{Style.RESET_ALL}")

def list_got(b):
    print(f"{Fore.BLUE}[*] Imported methods (GOT):")
    for function, address in b.got.items():
        print(f"{function}: {hex(address)}")
    print()

def list_gadgets(b):
    arch = b.arch
    context.log_level = 'ERROR'
    rop = ROP(b)
    rop.build()
    gadgets = rop.gadgets
    _syscall = rop.syscall 
    regl = []
    if arch == "amd64":
        regl = ["pop rax", "pop rbx", "pop rcx", "pop rdx", "pop rsi", "pop rdi", "pop rsi", "pop r8", "pop r9", "pop rsp" "pop rbp"]
    elif arch == "i386":
        regl = ["pop eax", "pop ebx", "pop ecx", "pop edx", "pop esi", "pop edi", "pop esi", "pop esp", "pop ebp"]

    print(f"{Fore.GREEN}[+] Gadgets:")
    for e in regl:
        x = rop.find_gadget([e, "ret"])
        if x:
            print(f"{hex(x.address)}: {x.insns}")
    if _syscall:
        print(f"{hex(_syscall.address)}: {_syscall.details.insns}")

def list_sections(b):
    data_addr = b.get_section_by_name('.data').header
    data_end = hex(data_addr.sh_size + data_addr.sh_addr)
    plt_addr = b.get_section_by_name('.plt').header
    plt_end = hex(data_addr.sh_size + data_addr.sh_addr)
    got_addr = b.get_section_by_name('.got').header
    got_end = hex(data_addr.sh_size + data_addr.sh_addr)
    text_addr = b.get_section_by_name('.got').header
    text_end = hex(data_addr.sh_size + data_addr.sh_addr)
    
    print(f"\n{Fore.BLUE}[*] Sections:\n")
    print(f".data:\n   Range: {hex(data_addr.sh_addr)}-{data_end}\n   Size: {hex(data_addr.sh_size)}")
    print(f".plt:\n   Range: {hex(plt_addr.sh_addr)}-{plt_end}\n   Size: {hex(plt_addr.sh_size)}")
    print(f".got:\n   Range: {hex(got_addr.sh_addr)}-{got_end}\n   Size: {hex(got_addr.sh_size)}")
    print(f".text:\n   Range: {hex(text_addr.sh_addr)}-{text_end}\n   Size: {hex(text_addr.sh_size)}\n")


def general_info(b,path):
    list_sections(b)

    if b.get_section_by_name('.dynamic'):
        print(f"{Fore.BLUE}[*] {Fore.WHITE}Dynamically linked\n")
        try:
            list_libs(b)
        except:
            pass
        list_got(b)
    else:
        print(f"{Fore.BLUE}[*] {Fore.WHITE}Statically Linked\n")

    list_gadgets(b)

    bin_sh = 0 
    try :
        bin_sh = next(b.search(b'/bin/sh'))
        print(f"[+] Interesting strings:\n \"/bin/sh\": {hex(bin_sh)}")
    except:
        pass

def main():
    parser = argparse.ArgumentParser(description="Octopwn - Automated ELF scanner for binary exploitation purposes")
    parser.add_argument('-f', '--file', type=str, required=True, help='Path to the ELF binary file')
    args = parser.parse_args()
    elf = ELF(args.file)
    general_info(elf,args.file)

if __name__ == "__main__":
    main()

