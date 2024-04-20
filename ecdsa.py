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

def ECDSA_generate_nonce(upper, lower):
    return randint(upper, lower)


def ECDSA_generate_keys():
    private_key = ECDSA_generate_nonce(1, ORDER - 1)
    public_key = mult(private_key, BaseU, BaseV, ORDER)
    return (private_key, public_key)


def ECDSA_sign(m, private_key):
    # k = ECDSA_generate_nonce(1, ORDER - 1)
    k = 0x2c92639dcf417afeae31e0f8fddc8e48b3e11d840523f54aaa97174221faee6
    r = (mult(k, BaseU, BaseV, ORDER))[0] % ORDER
    s = (mod_inv(k, ORDER) * (m + (r * private_key) % ORDER )) % ORDER
    return (r, s)    


def ECDSA_verify(m, r, s, public_key):
    if r <= 0 or r >= ORDER:
        return False
    if s <= 0 or s >= ORDER:
        return False
    
    s_inv = mod_inv(s, ORDER)
    u1 = (m * s_inv) % ORDER
    u2 = (r * s_inv) % ORDER

    point1 = mult(u1, BaseU, BaseV, ORDER)
    point2 = mult(u2, public_key[0], public_key[1], ORDER)
    recover_point = add(point1[0], point1[1], point2[0], point2[1], ORDER)
    v = recover_point[0] % ORDER
    print("v = ", hex(v))
    print("r - v = ", hex(r - v))
    return ((r - v) == 0) 

def main():
    ECDSA_generate_keys()
    m = H(str.encode("A very very important message !"))
    x = 0xc841f4896fe86c971bedbcf114a6cfd97e4454c9be9aba876d5a195995e2ba8
    X = mult(x, BaseU, BaseV, ORDER)
    # r = 0x429146a1375614034c65c2b6a86b2fc4aec00147f223cb2a7a22272d4a3fdd2
    # s = 0xf23bcdebe2e0d8571d195a9b8a05364b14944032032eeeecd22a0f6e94f8f33
    r, s = ECDSA_sign(m, x)
    print("r = ", hex(r))
    print("s = ", hex(s))
    print(ECDSA_verify(m, r, s, X))

if __name__ == '__main__':
    main()
