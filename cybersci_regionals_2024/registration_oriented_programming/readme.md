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
