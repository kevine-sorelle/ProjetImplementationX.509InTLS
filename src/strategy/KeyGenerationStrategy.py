from abc import ABC, abstractmethod


class KeyGenerationStrategy(ABC):
    """Abstract base class for key generation strategies"""
    @abstractmethod
    def generate_key(self, key_size: int):
        """Generate a key pair with specified key size"""
        pass


