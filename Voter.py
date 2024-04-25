import random
from dsa import DSA_sign
from ecdsa import ECDSA_sign
from algebra import int_to_bytes

class Voter:

    def __init__(self, sign_key):
        self.vote = [1, 0, 0, 0, 0]
        random.shuffle(self.vote)
        self.sign_key = sign_key

    def voting(self):
        return self.vote
    
    def sign(self, ballot, method='DSA'):
        if method == 'DSA':
            return DSA_sign(ballot, self.sign_key)
        elif method == 'ECDSA':
            return ECDSA_sign(ballot, self.sign_key)
