# Angr 

## Importing
```
import angr
```

## Logging

```
angr.l.setLevel("DEBUG")
```


## Create project

```
project = angr.Project("/bin/true")
```

# Show architecture information

```
>>> project.arch
<Arch AMD64 (LE)>
>>> project.arch.bits
64
>>> project.arch.registers
{'ip': (184, 8), 'rip': (184, 8), 'rdx': (32, 8), 'fs': (208, 8), 'fpround': (848, 8), 'rax': (16, 8), 'r13': (120, 8), 'rcx': (24, 8), 'pc': (184, 8), 'cc_op': (144, 8), 'sseround': (216, 8), 'r14': (128, 8), 'r15': (136, 8), 'r12': (112, 8), 'rsi': (64, 8), 'r10': (96, 8), 'r11': (104, 8), 'cc_ndep': (168, 8), 'bp': (56, 8), 'rsp': (48, 8), 'd': (176, 8), 'rbx': (40, 8), 'sp': (48, 8), 'r8': (80, 8), 'r9': (88, 8), 'rbp': (56, 8), 'cc_dep2': (160, 8), 'cc_dep1': (152, 8), 'rdi': (72, 8)}
```

# Show project information

```
# Entry point of binary
>>> hex(project.entry)
'0x4013e2'
 
# Print loader all objects
>>> project.loader.all_objects
 [<ELF Object test, maps [0x400000:0x60104f]>, <ELF Object libc-2.19.so, maps [0x1000000:0x13c42bf]>, <ELF Object ld-2.19.so, maps [0x2000000:0x22241c7]>, <TLSObj Object ##cle_tls##, maps [0x3000000:0x3030000]>, <AngrExternObject Object ##angr_externs##, maps [0x4000000:0x4004000]>]
  
   
# Print loader shared objects
>>> project.loader.shared_objects
{'ld-linux-x86-64.so.2': <ELF Object ld-2.19.so, maps [0x2000000:0x22241c7]>, 'libc.so.6': <ELF Object libc-2.19.so, maps [0x1000000:0x13c42bf]>}
    
# Print address of libc_start_main
>>> hex(project.loader.find_symbol_got_entry("__libc_start_main"))
'0x6060c0'
```

# Working with basic blocks

```
>>> block = project.factory.block(project.entry)
 
>>> hex(block.addr)
'0x4013e2L'
>>> print block._bytes
<cdata 'unsigned char *' 0x14f4ce2>
>>> print block.instructions
11
>>> print block.size       
41
 
>>> project.factory.block(project.entry).pp()   
0x4013e2:    xor    ebp, ebp
0x4013e4:    mov    r9, rdx
0x4013e7:    pop    rsi
0x4013e8:    mov    rdx, rsp
0x4013eb:    and    rsp, 0xfffffffffffffff0
0x4013ef:    push    rax
0x4013f0:    push    rsp
0x4013f1:    mov    r8, 0x403c60
0x4013f8:    mov    rcx, 0x403bf0
0x4013ff:    mov    rdi, 0x401340
0x401406:    call    0x401190
>>> project.factory.block(project.entry).vex.pp()
IRSB {
   t0:Ity_I32 t1:Ity_I32 t2:Ity_I32 t3:Ity_I64 t4:Ity_I64 t5:Ity_I64 t6:Ity_I64 t7:Ity_I64 t8:Ity_I64 t9:Ity_I64 t10:Ity_I64 t11:Ity_I64 t12:Ity_I64 t13:Ity_I64 t14:Ity_I64 t15:Ity_I32 t16:Ity_I64 t17:Ity_I32 t18:Ity_I64 t19:Ity_I64 t20:Ity_I64 t21:Ity_I64 t22:Ity_I64 t23:Ity_I64 t24:Ity_I64 t25:Ity_I64 t26:Ity_I64 t27:Ity_I64 t28:Ity_I64 t29:Ity_I64 t30:Ity_I64 t31:Ity_I64
 
   00 | ------ IMark(0x4013e2, 2, 0) ------
   01 | PUT(rbp) = 0x0000000000000000
   02 | ------ IMark(0x4013e4, 3, 0) ------
   03 | t21 = GET:I64(rdx)
   04 | PUT(r9) = t21
   05 | PUT(rip) = 0x00000000004013e7
   06 | ------ IMark(0x4013e7, 1, 0) ------
   07 | t4 = GET:I64(rsp)
   08 | t3 = LDle:I64(t4)
   09 | t22 = Add64(t4,0x0000000000000008)
   10 | PUT(rsi) = t3
   11 | ------ IMark(0x4013e8, 3, 0) ------
   12 | PUT(rdx) = t22
   13 | ------ IMark(0x4013eb, 4, 0) ------
   14 | t5 = And64(t22,0xfffffffffffffff0)
   15 | PUT(cc_op) = 0x0000000000000014
   16 | PUT(cc_dep1) = t5
   17 | PUT(cc_dep2) = 0x0000000000000000
   18 | PUT(rip) = 0x00000000004013ef
   19 | ------ IMark(0x4013ef, 1, 0) ------
   20 | t8 = GET:I64(rax)
   21 | t24 = Sub64(t5,0x0000000000000008)
   22 | PUT(rsp) = t24
   23 | STle(t24) = t8
   24 | PUT(rip) = 0x00000000004013f0
   25 | ------ IMark(0x4013f0, 1, 0) ------
   26 | t26 = Sub64(t24,0x0000000000000008)
   27 | PUT(rsp) = t26
   28 | STle(t26) = t24
   29 | ------ IMark(0x4013f1, 7, 0) ------
   30 | PUT(r8) = 0x0000000000403c60
   31 | ------ IMark(0x4013f8, 7, 0) ------
   32 | PUT(rcx) = 0x0000000000403bf0
   33 | ------ IMark(0x4013ff, 7, 0) ------
   34 | PUT(rdi) = 0x0000000000401340
   35 | PUT(rip) = 0x0000000000401406
   36 | ------ IMark(0x401406, 5, 0) ------
   37 | t28 = Sub64(t26,0x0000000000000008)
   38 | PUT(rsp) = t28
   39 | STle(t28) = 0x000000000040140b
   40 | t30 = Sub64(t28,0x0000000000000080)
   41 | ====== AbiHint(0xt30, 128, 0x0000000000401190) ======
   NEXT: PUT(rip) = 0x0000000000401190; Ijk_Call
}
```

# Path states
```
 project.factory.blank_state()
 project.factory.entry_state()
 project.factory.full_init_state()
 project.factory.path_group()
 project.factory.path()
```

# Graphing

```
from networkx.drawing.nx_agraph import write_dot
 
# Control Flow Graph
cfg = project.analyses.CFG()
# Value Flow Graph
vfg = project.analyses.VFG()
 
# Control Dependency Graph
cdg = project.analyses.CDG(cfg)
# Data Dependency Graph
ddg = project.analyses.DDG(cfg)
 
write_dot(cfg.graph, "/tmp/cfg.dot")
write_dot(vfg.graph, "/tmp/vfg.dot")
```
