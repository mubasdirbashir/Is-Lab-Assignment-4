import operator
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import binascii

def task1():
    p = 61
    q = 53
    n = p * q
    phi = operator.mul(operator.sub(p, 1), operator.sub(q, 1))
    e = 65537

    def egcd(a, b):
        if b == 0:
            return (a, 1, 0)
        g, x1, y1 = egcd(b, a % b)
        x = y1
        y = operator.sub(x1, operator.mul(a // b, y1))
        return (g, x, y)

    def modinv(a, m):
        g, x, y = egcd(a, m)
        if g != 1:
            raise Exception("modular inverse does not exist")
        return x % m

    d = modinv(e, phi)

    def text_to_int(text):
        return int.from_bytes(text.encode('utf-8'), 'big')

    def int_to_text(i):
        length = (i.bit_length() + 7) // 8
        return i.to_bytes(length, 'big').decode('utf-8', errors='ignore')

    def encrypt_int(m_int, pub_e, pub_n):
        return pow(m_int, pub_e, pub_n)

    def decrypt_int(c_int, priv_d, pub_n):
        return pow(c_int, priv_d, pub_n)

    message = "Ali"
    m_int = text_to_int(message)

    print("Task 1, Simple RSA")
    print("Public key n:", n)
    print("Public exponent:", e)

    if m_int >= n:
        print("Message too large")
    else:
        c = encrypt_int(m_int, e, n)
        print("Ciphertext integer:", c)
        m2 = decrypt_int(c, d, n)
        print("Decrypted text:", int_to_text(m2))


def task2():
    def generate_keypair(key_size=2048):
        key = RSA.generate(key_size)
        private_key_pem = key.export_key()
        public_key_pem = key.publickey().export_key()
        return key, private_key_pem, public_key_pem

    def encrypt_message(pub_key, message_bytes):
        cipher = PKCS1_OAEP.new(pub_key)
        return cipher.encrypt(message_bytes)

    def decrypt_message(priv_key, ciphertext):
        cipher = PKCS1_OAEP.new(priv_key)
        return cipher.decrypt(ciphertext)

    key, priv_pem, pub_pem = generate_keypair(2048)

    print("Task 2, RSA with PyCryptodome")
    print("Public key pem:")
    print(pub_pem.decode())
    print("Private key pem first 100 bytes:")
    print(priv_pem[:100].decode())

    user_message = "This is a test message for RSA with PyCryptodome"
    message_bytes = user_message.encode('utf-8')

    public_key = RSA.import_key(pub_pem)
    private_key = RSA.import_key(priv_pem)

    ciphertext = encrypt_message(public_key, message_bytes)
    print("Ciphertext hex:", binascii.hexlify(ciphertext).decode())

    decrypted = decrypt_message(private_key, ciphertext)
    print("Decrypted text:", decrypted.decode())


def task3():
    def generate_rsa_key(key_size=2048):
        return RSA.generate(key_size)

    def sign_message(private_key, message_bytes):
        h = SHA256.new(message_bytes)
        signer = pkcs1_15.new(private_key)
        return signer.sign(h)

    def verify_signature(public_key, message_bytes, signature):
        h = SHA256.new(message_bytes)
        verifier = pkcs1_15.new(public_key)
        try:
            verifier.verify(h, signature)
            return True
        except:
            return False

    key = generate_rsa_key()
    public_key = key.publickey()

    print("Task 3, Digital Signature")
    message = b"Important message to sign"

    signature = sign_message(key, message)
    print("Signature hex:", binascii.hexlify(signature).decode())

    ok = verify_signature(public_key, message, signature)
    print("Verification original:", ok)

    tampered = b"Important message to signinstead"
    ok2 = verify_signature(public_key, tampered, signature)
    print("Verification tampered:", ok2)


def menu():
    while True:
        print()
        print("Select Task")
        print("1 Simple RSA, manual math")
        print("2 RSA with PyCryptodome")
        print("3 Digital Signature")
        print("4 Exit")
        choice = input("Enter choice: ")

        if choice == "1":
            task1()
        elif choice == "2":
            task2()
        elif choice == "3":
            task3()
        elif choice == "4":
            break
        else:
            print("Invalid choice")

if __name__ == "__main__":
    menu()
