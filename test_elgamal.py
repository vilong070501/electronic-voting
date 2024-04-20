from elgamal import *

# Génération des clés
public_key, private_key = EG_generate_keys()

# Message à chiffrer
message = 42  # Peut être un vote, par exemple

# Chiffrement du message
encrypted_message = EGA_encrypt(message, public_key)

# Déchiffrement du message
decrypted_message = EG_decrypt(encrypted_message[0], encrypted_message[1], private_key)

print(f"Message original: {message}")
print(f"Message déchiffré: {decrypted_message}")
print(f"Message chiffré: {encrypted_message}")

