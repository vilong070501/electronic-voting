from VoteSystem import *

def prompt():

    encrypt, sign = 0, 0

    while (encrypt != 1 and encrypt != 2) or (sign != 1 and sign != 2):
        print()
        print("Please choose a method for encryption/decryption of your ballot")
        encrypt = int(input("\033[96m[1] ElGamal     [2] EC ElGamal \033[00m:   "))
        print("Please choose a method for signature verification of your ballot")
        sign = int(input("\033[93m[1] DSA         [2] ECDSA \033[00m:   "))

    return encrypt, sign

def main():

    encrypt, sign = prompt()

    encrypt_method = 'ElGamal' if encrypt == 1 else 'EC_ElGamal'
    sign_method = 'DSA' if sign == 1 else 'ECDSA'

    vote_system = VoteSystem(encrypt_method, sign_method)

    # vote_system.display_votes()

    for voter, public_sign_key in vote_system.voters:

        # Encrypt vote
        encrypted_vote = vote_system.encrypt_vote(voter.voting())

        for ballot in encrypted_vote:

            # Aggregate vote
            c1, c2 = ballot
            if vote_system.encrypt_method == 'ElGamal':
                b = int_to_bytes(c1) + int_to_bytes(c2)
            elif vote_system.encrypt_method == 'EC_ElGamal':
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
    
    # Display the result of the vote
    vote_system.display_result()
        

if __name__ == '__main__':
    main()