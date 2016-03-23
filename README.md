# ded
DOS Executable disassembler

```
Usage: ded <option> -f <file>
Options:
    -h    display this information
    -e    disassemble DOS MZ 16 bits executable
    -r    disassemble file using recursive traversal algorithm (experimental)
    -f    input file

Note:
    if no flags are given the input file is treated as a headerless 16 bits
    executable (.COM) and the linear sweep algorithm is used.
```


Requires: [Capstone Engine](http://www.capstone-engine.org) >= 3.0
