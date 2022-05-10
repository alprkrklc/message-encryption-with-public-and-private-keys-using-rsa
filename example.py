from crypto import KeyPair

JANE_PUBLIC_KEY_PATH = 'jane-public.pem'
JANE_PRIVATE_KEY_PATH = 'jane-private.pem'

JOHN_PUBLIC_KEY_PATH = 'john-public.pem'
JOHN_PRIVATE_KEY_PATH = 'john-private.pem'

def main():
    # We generate for both Jane and John a key pair.
    jane = KeyPair.generate_pair()
    john = KeyPair.generate_pair()

    # We save the pairs so we can access them whenever we need.
    jane.save(JANE_PUBLIC_KEY_PATH, JANE_PRIVATE_KEY_PATH)
    john.save(JOHN_PUBLIC_KEY_PATH, JOHN_PRIVATE_KEY_PATH)

    # We can load already existing key pairs very simply.
    jane_loaded = KeyPair.load(JANE_PUBLIC_KEY_PATH, JANE_PRIVATE_KEY_PATH)
    john_loaded = KeyPair.load(JOHN_PUBLIC_KEY_PATH, JOHN_PRIVATE_KEY_PATH)

    # We can check if saving and loading process working without any issue.
    assert jane.public_key == jane_loaded.public_key and jane.private_key == jane_loaded.private_key
    assert john.public_key == john_loaded.public_key and john.private_key == john_loaded.private_key

    # Let's demonstrate an encryption example now. 
    
    # Some random messages.
    from_jane = 'Hi John!'
    from_john = 'Hi Jane!'
    
    # Encrypt messages.
    to_john = jane.encrypt(from_jane, target_public_key=john.public_key)
    to_jane = john.encrypt(from_john, target_public_key=jane.public_key)

    # Decrypt encrypted messages.
    decrypted_by_john = john.decrypt(to_john)
    decrypted_by_jane = jane.decrypt(to_jane)

    print(f'''
    Encrypted by Jane: {to_john}.
    Decrypted by John: {decrypted_by_john}
    ''')
    
    print(f'''
    Encrypted by John: {to_jane}.
    Decrypted by Jane: {decrypted_by_jane}
    ''')
    
if __name__ == '__main__':
    main()
