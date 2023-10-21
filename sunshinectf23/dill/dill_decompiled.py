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


