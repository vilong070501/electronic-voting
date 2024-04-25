import unittest
import sys
import os

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

import elgamal
from algebra import int_to_bytes

class TestEGMEncryptMethod(unittest.TestCase):

    x, X = elgamal.EG_generate_keys()
    m1 = 0x2661b673f687c5c3142f806d500d2ce57b1182c9b25bfe4fa09529424b
    m2 = 0x1c1c871caabca15828cf08ee3aa3199000b94ed15e743c3

    def test_EGM_Encrypt_Verify(self):
        r1, c1 = elgamal.EGM_encrypt(self.m1, self.X)
        r2, c2 = elgamal.EGM_encrypt(self.m2, self.X)
        m3 = (self.m1 * self.m2)
        r3, c3 = elgamal.EGM_encrypt(m3, self.X)
        m4 = elgamal.EG_decrypt(r3, c3, self.x)
        # self.assertEqual(r3 % elgamal.PARAM_P, (r1 * r2) % elgamal.PARAM_P)
        # self.assertEqual((c1 * c2) % elgamal.PARAM_P, c3 % elgamal.PARAM_P)
        self.assertEqual(m4 % elgamal.PARAM_P, m3 % elgamal.PARAM_P)

    def test_EGM_Encrypt_Inverse_Verify(self):
        r1, c1 = elgamal.EGM_encrypt(self.m1, self.X)
        r2, c2 = elgamal.EGM_encrypt(self.m2, self.X)
        r3 = (r1 * r2)
        c3 = (c1 * c2)
        m3 = elgamal.EG_decrypt(r3, c3, self.x)
        self.assertEqual(m3 % elgamal.PARAM_P, (self.m1 * self.m2) % elgamal.PARAM_P)
        print()
        print(int_to_bytes(m3 % elgamal.PARAM_P).decode('utf-8'))

    def test_EGA_Encrypt_Result_Equal_3(self):
        m1, m2, m3, m4, m5 = 1, 0, 1, 1, 0
        r1, c1 = elgamal.EGA_encrypt(m1, self.X)
        r2, c2 = elgamal.EGA_encrypt(m2, self.X)
        r3, c3 = elgamal.EGA_encrypt(m3, self.X)
        r4, c4 = elgamal.EGA_encrypt(m4, self.X)
        r5, c5 = elgamal.EGA_encrypt(m5, self.X)
        r = (r1 * r2 * r3 * r4 * r5) % elgamal.PARAM_P
        c = (c1 * c2 * c3 * c4 * c5) % elgamal.PARAM_P
        gm = elgamal.EG_decrypt(r, c, self.x) % elgamal.PARAM_P
        m = elgamal.bruteLog(elgamal.PARAM_G, gm, elgamal.PARAM_P)
        self.assertEqual(m, 3)



if __name__ == '__main__':
    unittest.main()