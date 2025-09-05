"""
Dual-Layer Encryption Module

This module implements a two-layer encryption system using AES (symmetric) 
and RSA (asymmetric) cryptography for enhanced security.
"""

import os
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding as sym_padding, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import logging
from typing import Tuple, Optional, Dict

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DualEncryption:
    """
    Dual-layer encryption class implementing AES + RSA encryption/decryption.
    """
    
    def __init__(self):
        """Initialize the dual encryption system."""
        self.backend = default_backend()
        self.rsa_key_size = 2048
        self.aes_key_size = 32  # 256 bits
        
    def generate_rsa_keys(self) -> Tuple[bytes, bytes]:
        """
        Generate RSA public and private key pair.
        
        Returns:
            Tuple[bytes, bytes]: (private_key_pem, public_key_pem)
        """
        try:
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=self.rsa_key_size,
                backend=self.backend
            )
            
            # Get public key
            public_key = private_key.public_key()
            
            # Serialize keys to PEM format
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            logger.info("RSA key pair generated successfully")
            return private_pem, public_pem
            
        except Exception as e:
            logger.error(f"Error generating RSA keys: {str(e)}")
            raise
    
    def generate_aes_key(self, password: str = None, salt: bytes = None) -> Tuple[bytes, bytes]:
        """
        Generate AES key from password or create random key.
        
        Args:
            password (str, optional): Password for key derivation
            salt (bytes, optional): Salt for key derivation
            
        Returns:
            Tuple[bytes, bytes]: (aes_key, salt)
        """
        try:
            if password:
                # Generate salt if not provided
                if salt is None:
                    salt = os.urandom(16)
                
                # Derive key from password
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=self.aes_key_size,
                    salt=salt,
                    iterations=100000,
                    backend=self.backend
                )
                aes_key = kdf.derive(password.encode())
                
            else:
                # Generate random key
                aes_key = os.urandom(self.aes_key_size)
                salt = os.urandom(16)
            
            logger.info("AES key generated successfully")
            return aes_key, salt
            
        except Exception as e:
            logger.error(f"Error generating AES key: {str(e)}")
            raise
    
    def aes_encrypt(self, plaintext: str, aes_key: bytes) -> Dict[str, bytes]:
        """
        Encrypt plaintext using AES-256-CBC.
        
        Args:
            plaintext (str): Text to encrypt
            aes_key (bytes): AES encryption key
            
        Returns:
            Dict[str, bytes]: Dictionary containing 'ciphertext' and 'iv'
        """
        try:
            # Generate random IV
            iv = os.urandom(16)
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.CBC(iv),
                backend=self.backend
            )
            encryptor = cipher.encryptor()
            
            # Add PKCS7 padding
            padder = sym_padding.PKCS7(128).padder()
            padded_data = padder.update(plaintext.encode())
            padded_data += padder.finalize()
            
            # Encrypt
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            logger.info("AES encryption completed")
            return {
                'ciphertext': ciphertext,
                'iv': iv
            }
            
        except Exception as e:
            logger.error(f"Error in AES encryption: {str(e)}")
            raise
    
    def aes_decrypt(self, ciphertext: bytes, aes_key: bytes, iv: bytes) -> str:
        """
        Decrypt AES ciphertext.
        
        Args:
            ciphertext (bytes): Encrypted data
            aes_key (bytes): AES decryption key
            iv (bytes): Initialization vector
            
        Returns:
            str: Decrypted plaintext
        """
        try:
            # Create cipher
            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.CBC(iv),
                backend=self.backend
            )
            decryptor = cipher.decryptor()
            
            # Decrypt
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remove PKCS7 padding
            unpadder = sym_padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            
            logger.info("AES decryption completed")
            return plaintext.decode()
            
        except Exception as e:
            logger.error(f"Error in AES decryption: {str(e)}")
            raise
    
    def rsa_encrypt(self, data: bytes, public_key_pem: bytes) -> bytes:
        """
        Encrypt data using RSA public key.
        
        Args:
            data (bytes): Data to encrypt
            public_key_pem (bytes): RSA public key in PEM format
            
        Returns:
            bytes: Encrypted data
        """
        try:
            # Load public key
            public_key = serialization.load_pem_public_key(
                public_key_pem,
                backend=self.backend
            )
            
            # Encrypt data
            ciphertext = public_key.encrypt(
                data,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            logger.info("RSA encryption completed")
            return ciphertext
            
        except Exception as e:
            logger.error(f"Error in RSA encryption: {str(e)}")
            raise
    
    def rsa_decrypt(self, ciphertext: bytes, private_key_pem: bytes) -> bytes:
        """
        Decrypt data using RSA private key.
        
        Args:
            ciphertext (bytes): Encrypted data
            private_key_pem (bytes): RSA private key in PEM format
            
        Returns:
            bytes: Decrypted data
        """
        try:
            # Load private key
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None,
                backend=self.backend
            )
            
            # Decrypt data
            plaintext = private_key.decrypt(
                ciphertext,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            logger.info("RSA decryption completed")
            return plaintext
            
        except Exception as e:
            logger.error(f"Error in RSA decryption: {str(e)}")
            raise
    
    def dual_encrypt(self, message: str, public_key_pem: bytes, password: str = None) -> Dict[str, str]:
        """
        Perform dual-layer encryption: AES + RSA.
        
        Args:
            message (str): Message to encrypt
            public_key_pem (bytes): RSA public key
            password (str, optional): Password for AES key derivation
            
        Returns:
            Dict[str, str]: Dictionary containing encrypted data and metadata
        """
        try:
            # Step 1: Generate AES key
            aes_key, salt = self.generate_aes_key(password)
            
            # Step 2: Encrypt message with AES
            aes_result = self.aes_encrypt(message, aes_key)
            aes_ciphertext = aes_result['ciphertext']
            iv = aes_result['iv']
            
            # Step 3: Encrypt AES key with RSA
            rsa_encrypted_key = self.rsa_encrypt(aes_key, public_key_pem)
            
            # Step 4: Encode everything to base64 for safe transmission
            result = {
                'rsa_encrypted_key': base64.b64encode(rsa_encrypted_key).decode(),
                'aes_ciphertext': base64.b64encode(aes_ciphertext).decode(),
                'iv': base64.b64encode(iv).decode(),
                'salt': base64.b64encode(salt).decode() if password else None
            }
            
            logger.info("Dual-layer encryption completed successfully")
            return result
            
        except Exception as e:
            logger.error(f"Error in dual encryption: {str(e)}")
            raise
    
    def dual_decrypt(self, encrypted_data: Dict[str, str], private_key_pem: bytes, password: str = None) -> str:
        """
        Perform dual-layer decryption: RSA + AES.
        
        Args:
            encrypted_data (Dict[str, str]): Dictionary containing encrypted data
            private_key_pem (bytes): RSA private key
            password (str, optional): Password for AES key derivation
            
        Returns:
            str: Decrypted message
        """
        try:
            # Step 1: Decode from base64
            rsa_encrypted_key = base64.b64decode(encrypted_data['rsa_encrypted_key'])
            aes_ciphertext = base64.b64decode(encrypted_data['aes_ciphertext'])
            iv = base64.b64decode(encrypted_data['iv'])
            
            # Step 2: Decrypt AES key with RSA
            aes_key = self.rsa_decrypt(rsa_encrypted_key, private_key_pem)
            
            # Step 3: Decrypt message with AES
            decrypted_message = self.aes_decrypt(aes_ciphertext, aes_key, iv)
            
            logger.info("Dual-layer decryption completed successfully")
            return decrypted_message
            
        except Exception as e:
            logger.error(f"Error in dual decryption: {str(e)}")
            raise
    
    def save_keys(self, private_key: bytes, public_key: bytes, key_dir: str = "keys"):
        """
        Save RSA keys to files.
        
        Args:
            private_key (bytes): Private key in PEM format
            public_key (bytes): Public key in PEM format
            key_dir (str): Directory to save keys
        """
        try:
            # Create keys directory if it doesn't exist
            os.makedirs(key_dir, exist_ok=True)
            
            # Save private key
            with open(os.path.join(key_dir, "private_key.pem"), "wb") as f:
                f.write(private_key)
            
            # Save public key
            with open(os.path.join(key_dir, "public_key.pem"), "wb") as f:
                f.write(public_key)
            
            logger.info(f"Keys saved to {key_dir} directory")
            
        except Exception as e:
            logger.error(f"Error saving keys: {str(e)}")
            raise
    
    def load_key(self, key_path: str) -> bytes:
        """
        Load a key from file.
        
        Args:
            key_path (str): Path to the key file
            
        Returns:
            bytes: Key data
        """
        try:
            with open(key_path, "rb") as f:
                key_data = f.read()
            
            logger.info(f"Key loaded from {key_path}")
            return key_data
            
        except Exception as e:
            logger.error(f"Error loading key: {str(e)}")
            raise


def main():
    """
    Demo function to test the dual encryption functionality.
    """
    encryption = DualEncryption()
    
    print("Dual Encryption module initialized successfully")
    print("Supports AES-256-CBC + RSA-2048 encryption")
    
    # Example usage (commented out for safety)
    # private_key, public_key = encryption.generate_rsa_keys()
    # encrypted = encryption.dual_encrypt("Hello, World!", public_key)
    # decrypted = encryption.dual_decrypt(encrypted, private_key)
    # print(f"Original: Hello, World!")
    # print(f"Decrypted: {decrypted}")


if __name__ == "__main__":
    main()
