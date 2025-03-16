import os
import base64
from typing import Tuple, Dict

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


def generate_rsa_key_pair(key_size: int = 2048) -> Tuple[str, str]:
    """
    Genera un par de claves RSA.
    
    Args:
        key_size: Tamaño de la clave en bits
        
    Returns:
        Tuple[str, str]: Clave privada y pública en formato PEM
    """
    key = RSA.generate(key_size)
    private_key = key.export_key().decode('utf-8')
    public_key = key.publickey().export_key().decode('utf-8')
    return private_key, public_key


def encrypt_private_key(private_key: str, password: str) -> str:
    """
    Cifra una clave privada RSA con una contraseña.
    
    Args:
        private_key: Clave privada RSA en formato PEM
        password: Contraseña para cifrar la clave
        
    Returns:
        str: Clave privada cifrada en base64
    """
    # Derivar una clave AES de la contraseña
    password_hash = SHA256.new(password.encode()).digest()
    
    # Cifrar la clave privada con AES
    cipher = AES.new(password_hash, AES.MODE_CBC)
    iv = cipher.iv
    ciphertext = cipher.encrypt(pad(private_key.encode(), AES.block_size))
    
    # Combinar IV y texto cifrado y codificar en base64
    encrypted_data = base64.b64encode(iv + ciphertext).decode('utf-8')
    return encrypted_data


def decrypt_private_key(encrypted_private_key: str, password: str) -> str:
    """
    Descifra una clave privada RSA cifrada con una contraseña.
    
    Args:
        encrypted_private_key: Clave privada cifrada en base64
        password: Contraseña para descifrar la clave
        
    Returns:
        str: Clave privada RSA en formato PEM
    """
    # Derivar la clave AES de la contraseña
    password_hash = SHA256.new(password.encode()).digest()
    
    # Decodificar el texto cifrado
    encrypted_data = base64.b64decode(encrypted_private_key)
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    
    # Descifrar la clave privada
    cipher = AES.new(password_hash, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    
    return decrypted_data.decode('utf-8')


def hybrid_encrypt(message: str, recipient_public_key: str) -> Dict[str, str]:
    """
    Cifra un mensaje usando encriptación híbrida (RSA + AES).
    
    Args:
        message: Mensaje a cifrar
        recipient_public_key: Clave pública RSA del destinatario en formato PEM
        
    Returns:
        Dict[str, str]: Diccionario con el mensaje cifrado, la clave AES cifrada y el IV
    """
    # Generar una clave AES aleatoria
    aes_key = get_random_bytes(32)  # AES-256
    
    # Cifrar el mensaje con AES
    cipher_aes = AES.new(aes_key, AES.MODE_CBC)
    iv = cipher_aes.iv
    ciphertext = cipher_aes.encrypt(pad(message.encode('utf-8'), AES.block_size))
    
    # Cifrar la clave AES con RSA
    recipient_key = RSA.import_key(recipient_public_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    
    # Codificar en base64
    return {
        "encrypted_content": base64.b64encode(ciphertext).decode('utf-8'),
        "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode('utf-8'),
        "iv": base64.b64encode(iv).decode('utf-8')
    }


def hybrid_decrypt(
    encrypted_content: str,
    encrypted_aes_key: str,
    iv: str,
    private_key: str
) -> str:
    """
    Descifra un mensaje usando encriptación híbrida (RSA + AES).
    
    Args:
        encrypted_content: Mensaje cifrado en base64
        encrypted_aes_key: Clave AES cifrada en base64
        iv: Vector de inicialización en base64
        private_key: Clave privada RSA en formato PEM
        
    Returns:
        str: Mensaje descifrado
    """
    # Decodificar de base64
    ciphertext = base64.b64decode(encrypted_content)
    enc_aes_key = base64.b64decode(encrypted_aes_key)
    iv_bytes = base64.b64decode(iv)
    
    # Descifrar la clave AES con RSA
    recipient_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    aes_key = cipher_rsa.decrypt(enc_aes_key)
    
    # Descifrar el mensaje con AES
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv_bytes)
    padded_plaintext = cipher_aes.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)
    
    return plaintext.decode('utf-8')


def sign_message(message: str, private_key: str) -> str:
    """
    Firma un mensaje con una clave privada RSA.
    
    Args:
        message: Mensaje a firmar
        private_key: Clave privada RSA en formato PEM
        
    Returns:
        str: Firma digital en base64
    """
    key = RSA.import_key(private_key)
    h = SHA256.new(message.encode('utf-8'))
    signature = pkcs1_15.new(key).sign(h)
    return base64.b64encode(signature).decode('utf-8')


def verify_signature(message: str, signature: str, public_key: str) -> bool:
    """
    Verifica la firma de un mensaje.
    
    Args:
        message: Mensaje original
        signature: Firma digital en base64
        public_key: Clave pública RSA en formato PEM
        
    Returns:
        bool: True si la firma es válida, False en caso contrario
    """
    key = RSA.import_key(public_key)
    h = SHA256.new(message.encode('utf-8'))
    signature_bytes = base64.b64decode(signature)
    
    try:
        pkcs1_15.new(key).verify(h, signature_bytes)
        return True
    except (ValueError, TypeError):
        return False 