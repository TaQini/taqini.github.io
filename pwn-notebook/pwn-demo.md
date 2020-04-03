# 自动生成exp

```python 
#!/usr/bin/python
#__author__:TaQini

# pwn filename -> generate filename.py

from sys import argv
from os import system
from subprocess import *

def usage():
    print('$ pwn filename [exp.py]')
    print('    -> generate basic script for pwn')

if len(argv) < 2:
    usage()
else:
    filename = './'+argv[1]
    output = filename+'.py'
    if len(argv) > 2 :
    	output = argv[2]
    py = open(output,'w')

    header = "#!/usr/bin/python\n#coding=utf-8\n#__author__:TaQini\n\n"
    header+= "from pwn import *\n\n"

    fileinfo = "local_file  = "
    fileinfo+= '\''+ filename + '\'\n'
    fileinfo+= "local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'\n"
    fileinfo+= "remote_libc = local_libc # '../libc.so.6'\n\n"
    fileinfo+= "is_local = False\n"
    fileinfo+= "is_remote = False\n\n"

    process = "if len(sys.argv) == 1:\n"
    process+= "    is_local = True\n"
    process+= "    p = process(local_file)\n"
    process+= "    libc = ELF(local_libc)\n"
    process+= "elif len(sys.argv) > 1:\n"
    process+= "    is_remote = True\n"
    process+= "    if len(sys.argv) == 3:\n"
    process+= "        host = sys.argv[1]\n"
    process+= "        port = sys.argv[2]\n"
    process+= "    else:\n"
    process+= "        host, port = sys.argv[1].split(':')\n"
    process+= "    p = remote(host, port)\n"
    process+= "    libc = ELF(remote_libc)\n\n"
    process+= "elf = ELF(local_file)\n\n"

    context = "context.log_level = 'debug'\n"
    context+= "context.arch = elf.arch\n\n"

    pwncode = "se      = lambda data               :p.send(data) \n"
    pwncode+= "sa      = lambda delim,data         :p.sendafter(delim, data)\n"
    pwncode+= "sl      = lambda data               :p.sendline(data)\n"
    pwncode+= "sla     = lambda delim,data         :p.sendlineafter(delim, data)\n"
    pwncode+= "sea     = lambda delim,data         :p.sendafter(delim, data)\n"
    pwncode+= "rc      = lambda numb=4096          :p.recv(numb)\n"
    pwncode+= "ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)\n"
    pwncode+= "uu32    = lambda data               :u32(data.ljust(4, '\\0'))\n"
    pwncode+= "uu64    = lambda data               :u64(data.ljust(8, '\\0'))\n"
    pwncode+= "info_addr = lambda tag, addr        :p.info(tag + ': {:#x}'.format(addr))\n\n"

    debug = "def debug(cmd=''):\n"
    debug+= "    if is_local: gdb.attach(p,cmd)\n\n"

    info = "# info\n# gadget\n"
    # auto add gadget addr of pop rdi
    proc = Popen(['ROPgadget','--binary',filename],stdout=PIPE)
    grep = Popen(["grep","rdi"],stdin=PIPE,stdout=PIPE)
    gadget = grep.communicate(input=proc.stdout.read())

    info+= "prdi = " + gadget[0].replace(':','#') + '\n'
    info+= "# elf, libc\n\n# rop1\n"
    info+= "offset = 0\n"

    payload = "payload = 'A'*offset\npayload += ''\n\n"
    payload+= "# ru('')\n# sl(payload)\n\n"

    tailer = "# debug()\n"
    tailer+= "# info_addr('tag',addr)\n# log.warning('--------------')\n\n"
    tailer+= "p.interactive()\n\n"

    py.write(header)
    py.write(fileinfo)
    py.write(process)
    py.write(context)
    py.write(pwncode)
    py.write(debug)
    py.write(info)
    py.write(payload)
    py.write(tailer)
    py.close()

    system('chmod +x ' + output)
```

