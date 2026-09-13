"""Slow public-data arithmetic oracle, not constant-time production cryptography."""
import functools
import hashlib

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P-2, P) % P
I = pow(2, (P-1)//4, P)
IDENTITY = (0, 1, 1, 0)

def add(p, q):
    x, y, z, t = p
    a, b, c, d = q
    aa, bb, cc, dd = (y-x)*(b-a)%P, (y+x)*(b+a)%P, 2*D*t*d%P, 2*z*c%P
    e, f, g, h = bb-aa, dd-cc, dd+cc, bb+aa
    return (e*f%P, g*h%P, f*g%P, e*h%P)

def mul(p, n):
    result = IDENTITY
    while n:
        if n & 1:
            result = add(result, p)
        p = add(p, p)
        n >>= 1
    return result

def equal(p, q):
    return (p[0]*q[2]-q[0]*p[2])%P == 0 and (p[1]*q[2]-q[1]*p[2])%P == 0

def point(raw):
    if len(raw) != 32:
        raise ValueError('point-length')
    n = int.from_bytes(raw, 'little')
    y, sign = n & ((1 << 255)-1), n >> 255
    if y >= P:
        raise ValueError('noncanonical-y')
    y2 = y*y%P
    den = (D*y2+1)%P
    if not den:
        raise ValueError('point-denominator')
    x2 = (y2-1)*pow(den, P-2, P)%P
    x = pow(x2, (P+3)//8, P)
    if x*x%P != x2:
        x = x*I%P
    if x*x%P != x2 or (x == 0 and sign):
        raise ValueError('point-encoding')
    if (x & 1) != sign:
        x = P-x
    return (x, y, 1, x*y%P)

BASE = point(bytes.fromhex('58'+'66'*31))

@functools.lru_cache(maxsize=1024)
def admitted(raw):
    p = point(raw)
    if equal(p, IDENTITY) or not equal(mul(p, L), IDENTITY):
        raise ValueError('public-key-subgroup')
    return p

class Verifier:
    def admit(self, key):
        try:
            admitted(key)
            return True
        except ValueError:
            return False

    def verify(self, key, message, signature):
        try:
            if len(signature) != 64:
                return False
            a, r = admitted(key), point(signature[:32])
            s = int.from_bytes(signature[32:], 'little')
            if s >= L:
                return False
            k = int.from_bytes(hashlib.sha512(signature[:32]+key+message).digest(), 'little')%L
            return equal(mul(BASE, s), add(r, mul(a, k)))
        except ValueError:
            return False
