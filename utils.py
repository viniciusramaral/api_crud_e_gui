#=====================================================
#=====================================================
#Funções resposáveis pela criptografia de ponta a ponta
#=====================================================
#=====================================================


from cryptography.fernet import Fernet
import base64

def decrypt_data(encrypted_data, key):
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data)
    return decrypted_data.decode('utf-8')

def pad_base64(data):
    """Ensure Base64 string is correctly padded."""
    return data + '=' * (-len(data) % 4)
