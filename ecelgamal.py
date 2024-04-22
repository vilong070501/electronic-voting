from rfc7748 import x25519, add, sub, computeVcoordinate, mult
from algebra import mod_inv, int_to_bytes
from random import randint

p = 2**255 - 19
ORDER = (2**252 + 27742317777372353535851937790883648493)

BaseU = 9
BaseV = computeVcoordinate(BaseU)

def bruteECLog(C1, C2, p):
    s1, s2 = 1, 0
    for i in range(p):
        if s1 == C1 and s2 == C2:
            return i
        s1, s2 = add(s1, s2, BaseU, BaseV, p)
    return -1

def EGencode(message):
    if message == 0:
        return (1,0)
    if message == 1:
        return (BaseU, BaseV)
    
def EG_generate_nonce():
    return randint(1, ORDER - 1)

def ECEG_generate_keys():
    private_key = EG_generate_nonce()
    public_key = mult(private_key, BaseU, BaseV, ORDER)
    return (private_key, public_key)


def ECEG_encrypt(m, public_key):
    k = EG_generate_nonce()
    c1 = mult(k, BaseU, BaseV, ORDER)
    c2 = mult(k, public_key[0], public_key[1], ORDER)
    Pm = EGencode(m)
    return (c1, add(c2[0], c2[1], Pm[0], Pm[1], ORDER))


def ECEG_decrypt(c1, c2, private_key):
    tmp = mult(private_key, c1[0], c1[1], ORDER)
    Pm = sub(c2[0], c2[1], tmp[0], tmp[1], ORDER)
    return bruteECLog(Pm[0], Pm[1], ORDER)
