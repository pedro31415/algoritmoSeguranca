from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def encrypt_des(plaintext, key):
    iv = get_random_bytes(DES.block_size)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    padded_text = pad(plaintext, DES.block_size)
    ciphertext = cipher.encrypt(padded_text)
    return iv + ciphertext

def decrypt_des(ciphertext, key):
    iv = ciphertext[:DES.block_size]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    padded_text = cipher.decrypt(ciphertext[DES.block_size:])
    plaitext = unpad(padded_text, DES.block_size)
    return plaitext

if __name__ == "__main__":
    key = get_random_bytes(8)
    plaintext = input('Enter the plaintet: ').encode('utf-8')

    print(f'key: {key}')
    print()

    print(f'plaintext: {plaintext}')
    print()

    ciphertext = encrypt_des(plaintext, key)
    print(f'ciphertext: {ciphertext}')
    print()

    decrypted_text = decrypt_des(ciphertext, key)
    print(f'decrypted_text: {decrypted_text}')