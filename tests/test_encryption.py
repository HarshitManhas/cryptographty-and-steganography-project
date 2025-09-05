"""
Test suite for the dual encryption module.
"""

import pytest
import os
import sys
import tempfile

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from encryption.dual_encryption import DualEncryption


class TestDualEncryption:
    """Test class for dual encryption functionality."""
    
    @pytest.fixture
    def encryption(self):
        """Create a DualEncryption instance for testing."""
        return DualEncryption()
    
    @pytest.fixture
    def sample_message(self):
        """Sample message for testing."""
        return "This is a secret message for testing dual encryption."
    
    def test_rsa_key_generation(self, encryption):
        """Test RSA key pair generation."""
        private_key, public_key = encryption.generate_rsa_keys()
        
        assert isinstance(private_key, bytes)
        assert isinstance(public_key, bytes)
        assert b"BEGIN PRIVATE KEY" in private_key
        assert b"BEGIN PUBLIC KEY" in public_key
    
    def test_aes_key_generation_random(self, encryption):
        """Test random AES key generation."""
        aes_key, salt = encryption.generate_aes_key()
        
        assert isinstance(aes_key, bytes)
        assert isinstance(salt, bytes)
        assert len(aes_key) == 32  # 256 bits
        assert len(salt) == 16
    
    def test_aes_key_generation_from_password(self, encryption):
        """Test AES key generation from password."""
        password = "test_password_123"
        aes_key, salt = encryption.generate_aes_key(password)
        
        assert isinstance(aes_key, bytes)
        assert isinstance(salt, bytes)
        assert len(aes_key) == 32
        assert len(salt) == 16
        
        # Test that same password + salt produces same key
        aes_key2, _ = encryption.generate_aes_key(password, salt)
        assert aes_key == aes_key2
    
    def test_aes_encryption_decryption(self, encryption, sample_message):
        """Test AES encryption and decryption."""
        aes_key, _ = encryption.generate_aes_key()
        
        # Encrypt
        encrypted_result = encryption.aes_encrypt(sample_message, aes_key)
        
        assert 'ciphertext' in encrypted_result
        assert 'iv' in encrypted_result
        assert isinstance(encrypted_result['ciphertext'], bytes)
        assert isinstance(encrypted_result['iv'], bytes)
        
        # Decrypt
        decrypted_message = encryption.aes_decrypt(
            encrypted_result['ciphertext'],
            aes_key,
            encrypted_result['iv']
        )
        
        assert decrypted_message == sample_message
    
    def test_rsa_encryption_decryption(self, encryption):
        """Test RSA encryption and decryption."""
        private_key, public_key = encryption.generate_rsa_keys()
        test_data = b"Small data for RSA testing"
        
        # Encrypt
        ciphertext = encryption.rsa_encrypt(test_data, public_key)
        assert isinstance(ciphertext, bytes)
        assert ciphertext != test_data
        
        # Decrypt
        decrypted_data = encryption.rsa_decrypt(ciphertext, private_key)
        assert decrypted_data == test_data
    
    def test_dual_encryption_decryption(self, encryption, sample_message):
        """Test complete dual encryption and decryption process."""
        private_key, public_key = encryption.generate_rsa_keys()
        
        # Encrypt
        encrypted_data = encryption.dual_encrypt(sample_message, public_key)
        
        assert 'rsa_encrypted_key' in encrypted_data
        assert 'aes_ciphertext' in encrypted_data
        assert 'iv' in encrypted_data
        
        # Decrypt
        decrypted_message = encryption.dual_decrypt(encrypted_data, private_key)
        
        assert decrypted_message == sample_message
    
    def test_dual_encryption_with_password(self, encryption, sample_message):
        """Test dual encryption with password-based AES key."""
        private_key, public_key = encryption.generate_rsa_keys()
        password = "secure_password_123"
        
        # Encrypt
        encrypted_data = encryption.dual_encrypt(sample_message, public_key, password)
        
        assert 'salt' in encrypted_data
        assert encrypted_data['salt'] is not None
        
        # Decrypt
        decrypted_message = encryption.dual_decrypt(encrypted_data, private_key, password)
        
        assert decrypted_message == sample_message
    
    def test_key_save_load(self, encryption):
        """Test saving and loading keys."""
        private_key, public_key = encryption.generate_rsa_keys()
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Save keys
            encryption.save_keys(private_key, public_key, temp_dir)
            
            # Check files exist
            private_key_path = os.path.join(temp_dir, "private_key.pem")
            public_key_path = os.path.join(temp_dir, "public_key.pem")
            
            assert os.path.exists(private_key_path)
            assert os.path.exists(public_key_path)
            
            # Load keys
            loaded_private = encryption.load_key(private_key_path)
            loaded_public = encryption.load_key(public_key_path)
            
            assert loaded_private == private_key
            assert loaded_public == public_key
    
    def test_invalid_decryption_fails(self, encryption, sample_message):
        """Test that decryption fails with wrong keys."""
        private_key1, public_key1 = encryption.generate_rsa_keys()
        private_key2, public_key2 = encryption.generate_rsa_keys()
        
        # Encrypt with first key pair
        encrypted_data = encryption.dual_encrypt(sample_message, public_key1)
        
        # Try to decrypt with second private key (should fail)
        with pytest.raises(Exception):
            encryption.dual_decrypt(encrypted_data, private_key2)


if __name__ == "__main__":
    pytest.main([__file__])
