from rsa import newkeys, encrypt, decrypt
from rsa.key import PublicKey, PrivateKey

class KeyPair:
    def __init__(self, public_key: PublicKey, private_key: PrivateKey):
        self.public_key = public_key
        self.private_key = private_key
    
    @classmethod
    def generate_pair(cls, size=512):
        return cls(*newkeys(size))

    def save(self, public_key_path, private_key_path):
        with open(public_key_path, 'wb') as file1, open(private_key_path, 'wb') as file2:
            file1.write(self.public_key.save_pkcs1())
            file2.write(self.private_key.save_pkcs1())
    
    @classmethod
    def load(cls, public_key_path, private_key_path):
        with open(public_key_path, 'rb') as file1, open(private_key_path, 'rb') as file2:
            public_key = PublicKey.load_pkcs1(file1.read())
            private_key = PrivateKey.load_pkcs1(file2.read())

        return cls(public_key, private_key)

    def encrypt(self, message: str, target_public_key: PublicKey):
        '''Encrypt the message with target's public key, so only key which can decrypt the message is target's private key.'''
        return encrypt(message.encode(), target_public_key)

    def decrypt(self, encrypted_message: bytes):
        message = decrypt(encrypted_message, self.private_key)
        return message.decode()
