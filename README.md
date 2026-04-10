Vibe coded tool allowing pwners to give essential formation quickly
## Functionalities
* List mitigations, using checksec.
* List useful gadgets. Supported architectures: i386, amd64, arm and aarch64
* Create a minimalist pwntools template with 3 modes: local (default), remote and gdb debug.
## Installation
Make sure you have cmake and binutils installed.
```bash
git clone https://github.com/Octopuss78/Octopwn.git                                          
cd Octopwn                                                
pip install -r requirements.txt
ln -s $(pwd)/octopwn.py ~/.local/bin/octopwn
```
## Usage
 ```bash                                                                                      
  octopwn <binary> [--no-template]
                                                                                               
  Generated template                                        

  python3 xpl.py              # local process
  python3 xpl.py GDB          # gdb.debug with breakpoint on main
  python3 xpl.py REMOTE       # remote target                                                  
  python3 xpl.py REMOTE --host <ip> --port <port>
```
