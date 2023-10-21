# Flock of Seagulls

### Created by tj\_connor

> Ode to Seagulls - Chat GPT
> 
> In cyberspace they soar, a flock of seagulls, Guardians of data, with digital goggles. Their eyes keen for threats, they scan the waves, Protecting networks from the darkest caves.
> 
> With wings of encryption, they shield the skies, Defenders of secrets, where danger lies. In the realm of code, they glide and dive, Ensuring our data remains alive.
> 
> Cyber sentinels, they guard the shore, Against hackers' storms and breaches galore. In unity they fly, with vigilance and grace, These seagulls of security, in cyberspace.

### files
```sh
$ checksec ./flock
[*] '/home/kali/.../sunshinectf23/pwn/flock_of_seagulls/flock'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

# what is happening?

After reversing there are a series of functions (`func1`-`func5`) that are
called. These functions, with the exception of `funt1` and `main` all have the
similar form of the following code.

```c
void func3(void)

{
  long unaff_retaddr;
  
  func4();
  if (unaff_retaddr != 0x4012ca) {
    fail();
  }
  return;
}
```

This... is a little confusing to just look at, but it's a bit easier to analyze
the assembly and addresses associated to these functions.

```as
0000000000401293 <func3>:
  401293:	55                   	push   rbp
  401294:	48 89 e5             	mov    rbp,rsp
  401297:	48 83 ec 10          	sub    rsp,0x10
  40129b:	e8 c9 ff ff ff       	call   401269 <func4>
  4012a0:	48 8b 45 08          	mov    rax,QWORD PTR [rbp+0x8]
  4012a4:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
  4012a8:	48 8d 05 1b 00 00 00 	lea    rax,[rip+0x1b]        # 4012ca <func2+0xd>
  4012af:	48 39 45 f8          	cmp    QWORD PTR [rbp-0x8],rax
  4012b3:	74 05                	je     4012ba <func3+0x27>
  4012b5:	e8 1c ff ff ff       	call   4011d6 <fail>
  4012ba:	90                   	nop
  4012bb:	c9                   	leave
  4012bc:	c3                   	ret

00000000004012bd <func2>:
  4012bd:	55                   	push   rbp
  4012be:	48 89 e5             	mov    rbp,rsp
  4012c1:	48 83 ec 10          	sub    rsp,0x10
  4012c5:	e8 c9 ff ff ff       	call   401293 <func3>
  4012ca:	48 8b 45 08          	mov    rax,QWORD PTR [rbp+0x8]
  4012ce:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
  4012d2:	48 8d 05 17 00 00 00 	lea    rax,[rip+0x17]        # 4012f0 <func1+0x9>
  4012d9:	48 39 45 f8          	cmp    QWORD PTR [rbp-0x8],rax
  4012dd:	74 05                	je     4012e4 <func2+0x27>
  4012df:	e8 f2 fe ff ff       	call   4011d6 <fail>
  4012e4:	90                   	nop
  4012e5:	c9                   	leave
  4012e6:	c3                   	ret
```

Noting that, when the `ret` instruction is hit, the instruction pointer will
receive the address of the next instruction after the call into that function.
