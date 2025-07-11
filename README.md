# Octopwn

This is a simple tool to retrieve interesting information on an ELF binary, such as sections address, Mitigations and interesting gadgets

It has the following features:

* Determine Binary architecture
* Show binary protections (NX, RELRO, Canary, PIE, etc.)
* Print sections name, size and address ranges
* Imported functions from the GOT
* Interesting gadgets


For this first version, only Elf x64 and ELF x86 are supported but more architextures will be added on future commits.

Enjoy ;)

![](https://github.com/Octopuss78/Octopwn/blob/main/res/octopwn.png)
