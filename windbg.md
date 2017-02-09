# WinDBG CheatSheet



## Symbols



```powershell
# show symbol search path
.sympath

# OR
CTRL+S

# example symbol path including symbol server
srv*c:\symbols*https://msdl.microsoft.com/download/symbols

# reload symbols
.reload

# on mismatch errors like 'mismatched pdb'
# load symbols even when mismatching 
.reload /i 

# more verbosity for symbol loading
!sym noisy

# open help
.hh

# print loaded modules
lm

# print registers
r

# print memory (words)
dw 

.load "C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x86\\ext\\pykd.dll"
!py "C:\\Users\\Z\\Desktop\\TraceRecv.py"

# console
!py


```

```python
# setting breakpoint and handler

setBp(address, handler_func)

# print register
reg("eax")

# break to debugger
breakin()

# get address func from module
WS2 = module("ws2_32")
recv_address = filter(lambda x: "recv"  == x[0], WS2.enumSymbols())[0][1]

# print stack
print dbgCommand("dd 0x%08x" % reg("esp"))
```

