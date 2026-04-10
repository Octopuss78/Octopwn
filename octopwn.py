#!/usr/bin/env python3
import argparse, os, subprocess, shutil, sys
from pwn import *

VULN_FUNCS = ["gets", "scanf", "read", "strcpy", "memcpy", "fgets", "sprintf", "strcat"]

GADGETS_BY_ARCH = {
    "i386":    ["pop eax", "pop ebx", "pop ecx", "pop edx", "int 0x80", "ret", "leave"],
    "amd64":   ["pop rdi", "pop rsi", "pop rdx", "pop rax", "syscall", "ret", "leave"],
    "arm":     ["pop {r0", "pop {r1", "pop {r7", "svc #0", "bx lr", "mov r0"],
    "aarch64": ["ldr x0", "ldr x1", "ldr x8", "svc #0", "ret", "br x30"],
}


def checksec_info(elf):
    print(f"\n{'='*60}")
    print(f"[*] Binary: {elf.path}")
    print(f"[*] Arch:   {elf.arch} ({'64' if elf.bits == 64 else '32'}-bit)")
    print(f"{'='*60}")
    print(f"  RELRO:      {elf.relro or 'No RELRO'}")
    print(f"  Stack:      {'Canary found' if elf.canary else 'No canary'}")
    print(f"  NX:         {'NX enabled' if elf.nx else 'NX disabled'}")
    print(f"  PIE:        {'PIE enabled' if elf.pie else 'No PIE'}")
    print(f"  Stripped:   {'Yes' if elf.stripped else 'No'}")
    print(f"{'='*60}")

def check_dangerous_funcs(elf):
    print("\n[*] Checking for dangerous functions...")
    found = False
    for fn in ["system", "execve"]:
        if fn in elf.plt:
            print(f"  [!] {fn}() found in PLT @ {hex(elf.plt[fn])}")
            found = True
        elif fn in elf.symbols:
            print(f"  [!] {fn}() found in symbols @ {hex(elf.symbols[fn])}")
            found = True

    print("\n[*] Checking for vulnerable function calls...")
    for fn in VULN_FUNCS:
        addrs = []
        if fn in elf.plt:
            addrs.append(("PLT", elf.plt[fn]))
        if fn in elf.got:
            addrs.append(("GOT", elf.got[fn]))
        if fn in elf.symbols:
            addrs.append(("SYM", elf.symbols[fn]))
        if addrs:
            found = True
            for tag, addr in addrs:
                print(f"  [!] {fn}() [{tag}] @ {hex(addr)}")
            try:
                out = subprocess.check_output(
                    ["objdump", "-d", elf.path], stderr=subprocess.DEVNULL, text=True
                )
                count = sum(1 for line in out.splitlines() if f"<{fn}@plt>" in line or f"<{fn}>" in line)
                if count:
                    print(f"       -> ~{count} call(s) found in disassembly")
            except Exception:
                pass
    if not found:
        print("  [-] No dangerous functions found.")

def search_gadgets(binary_path, arch):
    # Try ROPgadget (bundled with pwntools), fallback to ropper
    tool = None
    for t in ["ROPgadget", "ropper"]:
        if shutil.which(t):
            tool = t
            break
    if not tool:
        print("\n[-] No gadget finder installed (ROPgadget/ropper), skipping.")
        return

    gadgets_to_find = GADGETS_BY_ARCH.get(arch, GADGETS_BY_ARCH.get("amd64"))
    print(f"\n[*] Searching interesting gadgets with {tool} ({arch})...")
    try:
        if tool == "ROPgadget":
            cmd = ["ROPgadget", "--binary", binary_path]
        else:
            cmd = ["ropper", "-f", binary_path, "--nocolor"]
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True, timeout=30)
    except Exception as e:
        print(f"  [-] {tool} failed: {e}")
        return
    found = False
    for g in gadgets_to_find:
        matches = [l.strip() for l in out.splitlines() if g.lower() in l.lower() and "0x" in l]
        if matches:
            found = True
            print(f"\n  [+] '{g}' ({len(matches)} found):")
            for m in matches[:5]:
                print(f"      {m}")
            if len(matches) > 5:
                print(f"      ... and {len(matches)-5} more")
    if not found:
        print("  [-] No interesting gadgets found.")

def gen_template(elf):
    bin_path = os.path.abspath(elf.path)

    tpl = f'''#!/usr/bin/env python3
import argparse
from pwn import *

context.binary = ELF("{bin_path}")
# context.terminal = ["tmux", "splitw", "-h"]

HOST, PORT = "127.0.0.1", 1337

def exploit(p):
    # TODO: write exploit
    p.interactive()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", nargs="?", default="LOCAL", choices=["LOCAL", "GDB", "REMOTE"])
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    args = parser.parse_args()

    if args.mode == "GDB":
        p = gdb.debug(context.binary.path, "b main")
    elif args.mode == "REMOTE":
        p = remote(args.host, args.port)
    else:
        p = process(context.binary.path)
    exploit(p)
'''
    out_path = os.path.join(os.path.dirname(bin_path), "xpl.py")
    with open(out_path, "w") as f:
        f.write(tpl)
    os.chmod(out_path, 0o755)
    print(f"\n[+] Template written to {out_path}")

def main():
    parser = argparse.ArgumentParser(description="octopwn - quick binary recon + template generator")
    parser.add_argument("binary", help="path to binary")
    parser.add_argument("--no-template", action="store_true", help="skip template generation")
    args = parser.parse_args()

    if not os.path.isfile(args.binary):
        print(f"[-] File not found: {args.binary}")
        sys.exit(1)

    context.log_level = "warn"
    elf = ELF(args.binary, checksec=False)

    checksec_info(elf)

    if not elf.stripped:
        check_dangerous_funcs(elf)
    else:
        print("\n[-] Binary is stripped, skipping symbol-based function checks.")

    search_gadgets(args.binary, elf.arch)

    if not args.no_template:
        gen_template(elf)

if __name__ == "__main__":
    main()
