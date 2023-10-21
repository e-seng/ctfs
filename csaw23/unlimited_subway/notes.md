# Unlimited Subway

### Created by 079

> Imagine being able to ride the subway for free, forever.

```sh
kali:unlimited_subway/ $ unzip -l share.zip 
Archive:  share.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
        0  2023-09-09 16:03   share/
    18736  2023-09-09 16:03   share/unlimited_subway
---------                     -------
    18736                     2 files

kali:unlimited_subway/ $ checksec ./share/unlimited_subway
[*] '/home/.../csaw23/pwn/unlimited_subway/share/unlimited_subway'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

The binary contains 5 user-defined functions.

- `int init (EVP_PKEY_CTX * ctx)`
- `int main (int argc, char ** argv)`
- `void print_flag (void)`
- `void print_menu (void)`
- `void view_account(char * account_details, int index)`

With a function existing called `print_flag` like that, it is not too hard to
conclude that this is a return to win. For this, the goal would be to overwrite
the return address in the working stack frame to the address of the
`print_flag()` function in memory. This is made simplier by the binary being a
non Position Independent Executable (PIE) one, and the binary will always be
placed at the same spot.

Looking at the disassembly of `unlimited_subway`, it can be quickly seen that
the `print_flag` function is located at addess `0x08049304`. However, one
security check that is in place that needs to be bypassed is the canary that is
present.
