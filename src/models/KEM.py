from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import hashlib
import struct

class KEM:
    """
    Key Encapsulation Mechanism (KEM) implementation based on Kyber concepts.
    
    This is a simplified implementation that demonstrates the key concepts
    of a KEM while using the cryptography library for the underlying operations.
    """
    
    def __init__(self, curve=ec.SECP256R1()):
        """
        Initialize the KEM with a specific elliptic curve.
        
        Args:
            curve: The elliptic curve to use (default: SECP256R1)
        """
        self.curve = curve
        self.backend = default_backend()
        
        # Generate a key pair
        self.private_key = ec.generate_private_key(curve, self.backend)
        self.public_key = self.private_key.public_key()
        
        # Parameters for the KEM
        self.shared_secret_length = 32  # 256 bits
        self.ciphertext_length = 64     # Length of the encapsulated key
    
    def encapsulate(self):
        """
        Encapsulate a shared secret using the public key.
        
        Returns:
            tuple: (encapsulated_key, shared_secret)
                - encapsulated_key: The public key and encrypted shared secret
                - shared_secret: The generated shared secret
        """
        # Generate a random shared secret
        shared_secret = os.urandom(self.shared_secret_length)
        
        # Generate a random ephemeral key pair for encapsulation
        ephemeral_private_key = ec.generate_private_key(self.curve, self.backend)
        ephemeral_public_key = ephemeral_private_key.public_key()
        
        # Get public key bytes for key derivation
        public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint
        )
        ephemeral_key_bytes = ephemeral_public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint
        )
        
        # Combine the points for key derivation
        combined = public_key_bytes + ephemeral_key_bytes
        
        # Derive a key using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'kem-encapsulation',
            backend=self.backend
        ).derive(combined)
        
        # Encrypt the shared secret using the derived key
        iv = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(derived_key),
            modes.CBC(iv),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        
        # Pad the shared secret to a multiple of 16 bytes
        padded_secret = self._pad(shared_secret)
        encrypted_secret = encryptor.update(padded_secret) + encryptor.finalize()
        
        # Combine the ephemeral public key, IV, and encrypted secret
        encapsulated_key = ephemeral_key_bytes + iv + encrypted_secret
        
        return encapsulated_key, shared_secret
    
    def decapsulate(self, encapsulated_key):
        """
        Decapsulate the shared secret using the private key.
        
        Args:
            encapsulated_key: The encapsulated key from encapsulate()
            
        Returns:
            bytes: The decapsulated shared secret
        """
        # Get the length of the public key bytes
        public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint
        )
        point_length = len(public_key_bytes)
        
        # Extract components from the encapsulated key
        ephemeral_point = encapsulated_key[:point_length]
        iv = encapsulated_key[point_length:point_length+16]
        encrypted_secret = encapsulated_key[point_length+16:]
        
        # Reconstruct the ephemeral public key
        ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            self.curve, ephemeral_point
        )
        
        # Derive the shared point
        shared_point = self.private_key.exchange(
            ec.ECDH(),
            ephemeral_public_key
        )
        
        # Combine the points for key derivation
        ephemeral_key_bytes = ephemeral_public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint
        )
        combined = public_key_bytes + ephemeral_key_bytes
        
        # Derive the same key using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'kem-encapsulation',
            backend=self.backend
        ).derive(combined)
        
        # Decrypt the shared secret
        cipher = Cipher(
            algorithms.AES(derived_key),
            modes.CBC(iv),
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        padded_secret = decryptor.update(encrypted_secret) + decryptor.finalize()
        
        # Unpad the shared secret
        shared_secret = self._unpad(padded_secret)
        
        return shared_secret
    
    def _pad(self, data):
        """PKCS7 padding"""
        block_size = 16
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    def _unpad(self, data):
        """PKCS7 unpadding"""
        padding_length = data[-1]
        return data[:-padding_length]
    
    def get_public_key_bytes(self):
        """Get the public key as bytes"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint
        )
    
    @classmethod
    def from_private_key_bytes(cls, private_key_bytes, curve=ec.SECP256R1()):
        """
        Create a KEM instance from a private key.
        
        Args:
            private_key_bytes: The private key as bytes
            curve: The elliptic curve to use
            
        Returns:
            KEM: A new KEM instance
        """
        kem = cls(curve)
        kem.private_key = ec.derive_private_key(
            int.from_bytes(private_key_bytes, byteorder='big'),
            curve,
            default_backend()
        )
        kem.public_key = kem.private_key.public_key()
        return kem
    
    def get_private_key_bytes(self):
        """Get the private key as bytes"""
        return self.private_key.private_numbers().private_value.to_bytes(
            (self.private_key.private_numbers().private_value.bit_length() + 7) // 8,
            byteorder='big'
        )