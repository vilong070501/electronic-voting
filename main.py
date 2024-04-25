from VoteSystem import *

def main():
    vote_system = VoteSystem('ElGamal', 'DSA')
    # vote_system = VoteSystem('ElGamal', 'ECDSA')
    # vote_system = VoteSystem('EC_ElGamal', 'DSA')
    # vote_system = VoteSystem('EC_ElGamal', 'ECDSA')
    vote_system.display_votes()

    for voter, public_sign_key in vote_system.voters:
        encrypted_vote = vote_system.encrypt_vote(voter.voting())
        for ballot in encrypted_vote:
            c1, c2 = ballot
            if vote_system.sign_method == 'DSA':
                b = int_to_bytes(c1) + int_to_bytes(c2)
            elif vote_system.sign_method == 'ECDSA':
                c = add(c1[0], c1[1], c2[0], c2[1], p)
                b = int_to_bytes(c[0]) + int_to_bytes(c[1])
            # Voter signs its ballot
            r, s = voter.sign(b, vote_system.sign_method)
            # Verify signature
            if not(vote_system.verify_vote((r, s), b, public_sign_key)):
                print("Signature is not verified !!!")
                exit(1)
        # If all ballots signature have been verified, add the vote to the system
        vote_system.add_vote(encrypted_vote)
    
    # Decrypt vote
    vote_system.decrypt_votes()
        

if __name__ == '__main__':
    main()