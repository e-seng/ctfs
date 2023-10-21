#!/usr/bin/env python3

# time to try to regenerate the flag :)

class Dill:
    prefix = "sun{"
    suffix = "}"
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

    flag_len = 32

    def __init__(self):
        self.encrypted = 'bGVnbGxpaGVwaWNrdD8Ka2V0ZXRpZGls'

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
