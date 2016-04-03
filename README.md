# ded
DOS Executable disassembler

```
Usage: ded <option> -f <file>
Options:
    -H    display this information
    -e    disassemble DOS MZ 16 bits executable
    -h    if -e display the DOS MZ header
    -r    disassemble file using recursive traversal algorithm (experimental)
    -f    input file

Note:
    if no flags are given the input file is treated as a headerless 16 bits
    executable (.COM) and the linear sweep algorithm is used.
```


Requires: [Capstone Engine](http://www.capstone-engine.org) >= 3.0
