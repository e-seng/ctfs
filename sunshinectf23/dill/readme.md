# Dill

> Originally this was going to be about pickles, but .pyc sounds close enough to "pickles" so I decided to make it about that instead.

### files

```sh
$ file dill.cpython-38.pyc 
dill.cpython-38.pyc: Byte-compiled Python module for CPython 3.8, timestamp-based, .py timestamp: Fri Oct  6 19:53:54 2023 UTC, .py size: 914 bytes
```

## Decompilation

Based off information of the provided file to reverse, the provided binary is a
compiled cpython module. As a result, it needs to be deompiled into something
that is actually legible so we can properly reverse it.

After some research, some decompilers were found. `decompyle3` is one, which
seems to work for others, but did not work for me, likely because I was using
python3.11, which borks so many modules :). Instead,
[zrax/pycdc](https://github.com/zrax/pycdc) worked really well for me! After
compiling (+ researching actually how to, note: use `cmake .`), the following
decompiled python3 "script" works.

```py
# Source Generated with Decompyle++
# File: dill.cpython-38.pyc (Python 3.8)


class Dill:
    prefix = 'sun{'
    suffix = '}'
    o = [
        5,
        1,
        3,
        4,
        7,
        2,
        6,
        0]
    
    def __init__(self = None):
        self.encrypted = 'bGVnbGxpaGVwaWNrdD8Ka2V0ZXRpZGls'

    
    def validate(self = None, value = None):
        if not value.startswith(Dill.prefix) or value.endswith(Dill.suffix):
            return False
        value = None[len(Dill.prefix):-len(Dill.suffix)]
        if len(value) != 32:
            return False
        c = (lambda .0 = None: [ value[i:i + 4] for i in .0 ])(range(0, len(value), 4))
        value = None((lambda .0 = None: [ c[i] for i in .0 ])(Dill.o))
        if value != self.encrypted:
            return False

```

It should be noted that this decompiled script _cannot_ but run as-is,
particularly with the number of subset or constructor calls for the `None` type.
It being the `None` type, these calls should not be made possible. After
additional investigation, a lot of these calls would make sense if the `None`
type was replaced by the `str` type. This is further suggested by the `value`
parameter of `validate(...)`, which is manipulated on and then compared against
the `.encrypted` attribute, of type `str`. Looking at the other attributes,
particularly the `.prefix` and `.suffix` attributes, it can be quickly
determined that the `value` is supposed to be the flag itself, especially lines
22-23. Therefore, this `pyc` module is one that reads a given string and checks
whether it is the flag.

```py
        if not value.startswith(Dill.prefix) or value.endswith(Dill.suffix):
            return False
```

So, the question is, what is the flag? To determine this, the encrypted version
of the flag can be reversed, especially since no cryptographic hashing is
occurring.

## What is actually happening?

The core part which encrypts the value parameter occurs on lines 28-29. The
equivalent, more readable versions of these lines are as follows, expanding out
the lambda functions.

```py
    # c = (lambda .0 = None: [ value[i:i + 4] for i in .0 ])(range(0, len(value), 4))
    def c(self, value):
        output = []

        for i in range(0, len(value), 4):
            output[i] = value[i:i+4]

        return output

    # value = None((lambda .0 = None: [ c[i] for i in .0 ])(Dill.o))
    # the None cast here is probably a str cast
    def encrypt_flag(self, c):
        return str([ c[i] for i in Dill.o ])
```

Although it's not immediately obvious, these two functions chunk the flag
(value) into 4 character parts. The second line, now the `encrypt_flag(...)`
function, then takes those chunks and re-orders them by `Dill.o`. `Dill.o`
contains a list of intergers, all unique, starting on zero, and continuous if
sorted in order. As such, `Dill.o` indicates the new order the chunks needed to
be placed in to get the encrypted flag.

## Regenerating the flag

Knowing that the encrypted flag is made by splitting and reordering the flag by
4-character chunks, the encrypted flag can then be split into 4-character chunks
and ordered in reverse to generate the flag. The order of each chunk will be the
inverse of `Dill.o`. That being, if `Dill.o` maps the index of each encrypted
chunk to the index of the unencrypted part, then the inverse of `Dill.o` maps
the index of each unencrypted chunk to the index of the encrypted part. This
gives the code below.

```py
    o = [
        5,
        1,
        3,
        4,
        7,
        2,
        6,
        0]

    o_inverted = [ # this maps the location of each index in o
        7, # ie. here, the index=0 is in the 7th index in o
        1,
        5,
        2,
        3,
        0,
        6,
        4,
    ]
```

The code to decrypt the encrypted flag is then similar to that which encrypts
it, but just using `Dill.o_inverted` rather than `Dill.o`. This, in turn, gives
the remainder of the code that provides the flag.

```py
    def chunk_encrypted(self):
        return [self.encrypted[i:i + 4] for i in range(0, len(self.encrypted), 4)]
                                                # note the increments by 4!
                                                # these increments force the
                                                # chunks into 8 parts

    def decrypt_flag(self):
        c_rev = []
        chunked_encrypted = self.chunk_encrypted()
        for section in Dill.o_inverted:
            c_rev.append(chunked_encrypted[section])

        return Dill.prefix + ''.join(c_rev) + Dill.suffix

if __name__ == "__main__":
    dill = Dill()
    print("[*] Flag!", dill.decrypt_flag())
```

`sun{ZGlsbGxpa2V0aGVwaWNrbGVnZXRpdD8K}`
