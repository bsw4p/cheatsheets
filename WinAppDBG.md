# WinappDBG

---

## What?

* Python debugger based on windows debugging API.
* Developed by "Mario Vilas" (https://twitter.com/mario_vilas)
* Open Source: 
  * https://github.com/MarioVilas/winappdbg
  * http://winappdbg.readthedocs.io/en/latest/
  
---

## Why?

- easy to use

- easy to setup

- good documentation

- still maintained :)

---

## Install

1. Install python (https://www.python.org/downloads/windows/)
2. VisualC++ redistributable 2015 (https://www.microsoft.com/de-de/download/details.aspx?id=48145)
3. Install capstone engine (https://github.com/aquynh/capstone/releases/download/3.0.5-rc2/capstone-3.0.5-rc2-python-win32.msi)
4. Get winappdbg source (https://github.com/MarioVilas/winappdbg/archive/winappdbg_v1.6.zip) or github
5. run install.bat from winappdbg folder

---

## Examples

---


### List processes

```python
from winappdbg import System

# Create a system snaphot.
system = System()

# Now we can enumerate the running processes.
for process in system:
    print("%d:\t%s" %
    	(process.get_pid(),process.get_filename()))
```

---


### Starting processes

```python
from winappdbg import System

import sys

# Instance a System object.
system = System()

# Get the target application.
command_line = system.argv_to_cmdline( sys.argv[ 1 : ] )

# Start a new process.
# (see the docs for more options)
process = system.start_process( command_line ) 

# Show info on the new process.
print "Started process %d (%d bits)" % 
	( process.get_pid(), process.get_bits() )
```

---

### Show imports

```python
from winappdbg import Process, HexDump

def print_threads_and_modules( pid ):

    # Instance a Process object.
    process = Process( pid )
    print "Process %d" % process.get_pid()

    # Now we can enumerate the threads in the process...
    print "Threads:"
    for thread in process.iter_threads():
        print "\t%d" % thread.get_tid()

    # ...and the modules in the process.
    print "Modules:"
    bits = process.get_bits()
    for module in process.iter_modules():
        print "\t%s\t%s" % (
            HexDump.address( module.get_base(), bits ),
            module.get_filename()
        )
```

---

### Read memory

```python
from winappdbg import Process

pid = 23

# Instance a Process object.
process = Process( pid )

# Read the process memory.
data = process.read( address, length )

# You can also change the process memory.
# process.write( address, "example data" )

return data
```

---

### Inject DLLs

```python
from winappdbg import Process

pid = 23
filename = "foo.dll"

# Instance a Process object.
process = Process( pid )

# Load the DLL library in the process.
process.inject_dll( filename )
```

---

### Search memory

```python
pid = 23

process = Process( pid )

# Search for the string in the process memory.
for address in process.search_bytes( bytes ):
        # Print the memory address where it was found.
        print HexDump.address( address )
```

---

### Breakpoints

```python
# This function will be called when our breakpoint is hit.
def action_callback( event ):
    process = event.get_process()
    thread  = event.get_thread()

    # Get the address of the top of the stack.
    stack   = thread.get_sp()

    # Get the return address of the call.
    address = process.read_pointer( stack )

    # Read register eax
    eax = event.get_thread().get_register('Eax')
    
    # Get the process and thread IDs.
    pid     = event.get_pid()
    tid     = event.get_tid()

    # Show a message to the user.
    message = "kernel32!CreateFileW called from " +
    			"%s by thread %d at process %d"
    print message % ( 
    HexDump.address(address, process.get_bits()), tid, pid )
    # ...
```

---

```python
...
class MyEventHandler( EventHandler ):
    def load_dll( self, event ):
        # Get the new module object.
        module = event.get_module()

        # If it's kernel32.dll...
        if module.match_name("kernel32.dll"):

            # Get the process ID.
            pid = event.get_pid()

            # Get the address of CreateFile.
            address = module.resolve( "CreateFileW" )

            # Set a breakpoint at CreateFile.
            event.debug.break_at( 
            	pid, address, action_callback )
```

---

### Hooking

```python
from winappdbg.win32 import PVOID


# This function will be called when the hooked function is entered.
def wsprintf( event, ra, lpOut, lpFmt ):
    # Get the format string.
    process = event.get_process()
    lpFmt   = process.peek_string( lpFmt, fUnicode = True )

    # Get the vararg parameters.
    count      = lpFmt.replace( '%%', '%' ).count( '%' )
    thread     = event.get_thread()
    if process.get_bits() == 32:
        parameters = thread.read_stack_dwords(
        	count, offset = 3)
    else:
        parameters = thread.read_stack_qwords(
        	count, offset = 3)

    # Show a message to the user.
    showparams = ", ".join( [ hex(x) for x in parameters ] )
    print "wsprintf( %r, %s );" % ( lpFmt, showparams )
    # ...
```
---

```python
class MyEventHandler( EventHandler ):
    def load_dll( self, event ):
        # Get the new module object.
        module = event.get_module()
        # If it's user32...
        if module.match_name("user32.dll"):
            # Get the process ID.
            pid = event.get_pid()
            # Get the address of wsprintf.
            address = module.resolve( "wsprintfW" )
            # This is an approximated signature of the 
            # wsprintf function.
            # Pointers must be void so ctypes doesn't try to 
            # read from them.
            # Varargs are obviously not included.
            signature = ( PVOID, PVOID )

            # Hook the wsprintf function.
            event.debug.hook_function( 
            	pid, address, wsprintf, signature=signature)

            # Use stalk_function instead of hook_function
            # to be notified only the first time the  
            # function is called.
            # event.debug.stalk_function( ... )
```

---


And much much much more at: http://winappdbg.readthedocs.io/en/latest/ProgrammingGuide.html


---

# DEMO

....
