from rfc7748 import x25519, add, computeVcoordinate, mult
from Crypto.Hash import SHA256
from random import randint
from algebra import mod_inv

p = 2**255 - 19
ORDER = (2**252 + 27742317777372353535851937790883648493)

BaseU = 9
BaseV = computeVcoordinate(BaseU)


def H(message):
    h = SHA256.new(message)
    return (int(h.hexdigest(), 16))

def ECDSA_generate_nonce():
    return randint(1, ORDER - 1)


def ECDSA_generate_keys():
    private_key = ECDSA_generate_nonce()
    public_key = mult(private_key, BaseU, BaseV, p)
    return (private_key, public_key)


def ECDSA_sign(message, private_key):
    k = ECDSA_generate_nonce()
    R = mult(k, BaseU, BaseV, p)
    r = R[0] % ORDER
    if r == 0:
        return ECDSA_sign(message, private_key)
    h = H(message)
    s = (mod_inv(k, ORDER) * (h + r * private_key)) % ORDER
    if s == 0:
        return ECDSA_sign(message, private_key)
    return (r, s)    


def ECDSA_verify(message, r, s, public_key):
    if r <= 0 or r >= ORDER:
        return False
    if s <= 0 or s >= ORDER:
        return False
    
    h = H(message)
    s_inv = mod_inv(s, ORDER)
    u1 = (h * s_inv) % ORDER
    u2 = (r * s_inv) % ORDER

    point1 = mult(u1, BaseU, BaseV, p)
    point2 = mult(u2, public_key[0], public_key[1], p)
    recover_point = add(point1[0], point1[1], point2[0], point2[1], p)
    v = recover_point[0] % ORDER
    return (r == v)
