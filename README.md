# ded
DOS Executable disassembler

```
Usage: ded <option> -f <file>
Options:
    -H    display this information
    -m    disassemble DOS MZ 16 bits executable
    -h    if -e display the DOS MZ header
    -r    disassemble file using recursive traversal algorithm (experimental)
    -v    verbose mode: if -r display the list of addresses found
    -e    specifies an entry point
    -s    specifies instructions syntax (att, intel, masm) - default is 'intel'
    -f    input file

Note:
    if no flags are given the input file is treated as a headerless 16 bits
    executable (.COM) and the linear sweep algorithm is used.
```


#### Dependencies
* [Capstone Engine](http://www.capstone-engine.org) >= 4.0
* [fmtlib](https://github.com/fmtlib/fmt)
