"""
RSA Encryption Implementation

This module implements RSA encryption for secure messaging in the friend network.
It uses the core communication system (core_communication.py) and adds RSA functionality.

Features implemented:
- RSA key generation (public/private key pairs)
- Message encryption using receiver's public key
- Message decryption using receiver's private key
- Integration with the core messaging system
- Proper metadata indicating RSA encryption

Author: Michaela Gillan
Team: Group 8
"""

import json
import math
import random
import base64
from typing import Tuple, Dict

# Import the core system
from core_communication import CommunicationNetwork, Message, Person

# =============================================================================
# RSA CRYPTOGRAPHIC FUNCTIONS
# =============================================================================

def is_prime(n: int) -> bool:
    """
    Check if a number is prime using trial division.
    
    Args:
        n: Number to test for primality
        
    Returns:
        True if n is prime, False otherwise
    """
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    
    for i in range(3, int(math.sqrt(n)) + 1, 2):
        if n % i == 0:
            return False
    return True

def generate_prime(min_val: int = 100, max_val: int = 1000) -> int:
    """
    Generate a random prime number in the specified range.
    
    Args:
        min_val: Minimum value for the prime
        max_val: Maximum value for the prime
        
    Returns:
        A random prime number in the range [min_val, max_val]
    """
    while True:
        candidate = random.randint(min_val, max_val)
        if is_prime(candidate):
            return candidate

def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Extended Euclidean Algorithm.
    
    Args:
        a, b: Integers to find extended GCD for
        
    Returns:
        Tuple (gcd, x, y) where gcd = ax + by
    """
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def mod_inverse(e: int, phi: int) -> int:
    """
    Calculate modular multiplicative inverse of e modulo phi.
    
    Args:
        e: Number to find inverse of
        phi: Modulus
        
    Returns:
        Modular inverse of e mod phi
        
    Raises:
        ValueError: If inverse doesn't exist
    """
    gcd, x, _ = extended_gcd(e, phi)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    return (x % phi + phi) % phi

def generate_rsa_keys() -> Tuple[Tuple[int, int], Tuple[int, int]]:
    """
    Generate an RSA public/private key pair.
    
    Returns:
        Tuple of (public_key, private_key) where each key is (n, exponent)
        public_key = (n, e), private_key = (n, d)
    """
    # Step 1: Generate two distinct prime numbers
    p = generate_prime(100, 500)
    q = generate_prime(100, 500)
    while q == p:  # Ensure they're different
        q = generate_prime(100, 500)
    
    # Step 2: Calculate n and phi(n)
    n = p * q
    phi = (p - 1) * (q - 1)
    
    # Step 3: Choose e (public exponent)
    # Common choices are 3, 17, or 65537. We'll use a smaller value for demo.
    e = 65537
    while math.gcd(e, phi) != 1:
        e += 2  # Find next odd number that's coprime to phi
    
    # Step 4: Calculate d (private exponent)
    d = mod_inverse(e, phi)
    
    public_key = (n, e)
    private_key = (n, d)
    
    return public_key, private_key

# =============================================================================
# RSA MESSAGING IMPLEMENTATION
# =============================================================================

class RSAMessaging:
    """
    RSA encryption functionality for the communication system.
    
    This class provides all the methods needed to send and receive
    RSA encrypted messages using the core communication system.
    """
    
    @staticmethod
    def setup_person_keys(person: Person):
        """
        Generate and assign RSA keys to a person.
        
        This adds public_key and private_key attributes to the Person object.
        
        Args:
            person: Person object to add keys to
        """
        public_key, private_key = generate_rsa_keys()
        person.public_key = public_key
        person.private_key = private_key
    
    @staticmethod
    def encrypt_message(plaintext: str, public_key: Tuple[int, int]) -> Tuple[str, Dict]:
        """
        Encrypt a plaintext message using RSA public key encryption.
        
        Args:
            plaintext: The message to encrypt
            public_key: Tuple of (n, e) representing the public key
            
        Returns:
            Tuple of (encrypted_message, metadata) where:
            - encrypted_message is base64-encoded encrypted data
            - metadata contains encryption information
            
        Raises:
            ValueError: If any character's ASCII value is >= n (key too small)
        """
        n, e = public_key
        
        # Convert each character to its ASCII value
        message_ints = [ord(char) for char in plaintext]
        
        # Encrypt each character separately
        encrypted_ints = []
        for char_int in message_ints:
            # Ensure character value fits within our key size
            if char_int >= n:
                raise ValueError(f"Character ASCII value {char_int} too large for key size n={n}")
            
            # RSA encryption: c = m^e mod n
            encrypted_val = pow(char_int, e, n)
            encrypted_ints.append(encrypted_val)
        
        # Convert to JSON and then base64 for safe transmission
        encrypted_json = json.dumps(encrypted_ints)
        encrypted_b64 = base64.b64encode(encrypted_json.encode()).decode()
        
        # Create metadata as required by assignment
        metadata = {
            "encryption": "rsa",
            "original_length": len(plaintext),
            "encrypted_length": len(encrypted_b64),
            "public_key_n": n,
            "public_key_e": e,
            "character_count": len(message_ints)
        }
        
        return encrypted_b64, metadata
    
    @staticmethod
    def decrypt_message(encrypted_message: str, private_key: Tuple[int, int]) -> str:
        """
        Decrypt an RSA encrypted message using the private key.
        
        Args:
            encrypted_message: Base64-encoded encrypted message
            private_key: Tuple of (n, d) representing the private key
            
        Returns:
            Decrypted plaintext message
            
        Raises:
            ValueError: If decryption fails
        """
        n, d = private_key
        
        try:
            # Decode from base64 and parse JSON
            encrypted_json = base64.b64decode(encrypted_message.encode()).decode()
            encrypted_ints = json.loads(encrypted_json)
            
            # Decrypt each integer back to a character
            decrypted_chars = []
            for encrypted_val in encrypted_ints:
                # RSA decryption: m = c^d mod n
                decrypted_val = pow(encrypted_val, d, n)
                decrypted_chars.append(chr(decrypted_val))
            
            return ''.join(decrypted_chars)
            
        except Exception as e:
            raise ValueError(f"RSA decryption failed: {str(e)}")
    
    @staticmethod
    def send_encrypted_message(network: CommunicationNetwork, sender_id: str, 
                             receiver_id: str, plaintext: str) -> bool:
        """
        Send an RSA encrypted message through the communication network.
        
        This method integrates RSA encryption with the core messaging system.
        It encrypts the message with the receiver's public key and sends it
        as an "rsa_encrypted" message type.
        
        Args:
            network: CommunicationNetwork instance
            sender_id: ID of the message sender
            receiver_id: ID of the message receiver
            plaintext: The message to encrypt and send
            
        Returns:
            True if message was successfully sent, False otherwise
        """
        # Get sender and receiver from network
        sender = network.get_person(sender_id)
        receiver = network.get_person(receiver_id)
        
        if not sender or not receiver:
            print(f"Error: Could not find sender '{sender_id}' or receiver '{receiver_id}' in network")
            return False
        
        # Ensure receiver has RSA keys
        if not hasattr(receiver, 'public_key') or not receiver.public_key:
            print(f"Setting up RSA keys for {receiver.name}")
            RSAMessaging.setup_person_keys(receiver)
        
        # Ensure sender has keys too (for completeness)
        if not hasattr(sender, 'public_key') or not sender.public_key:
            RSAMessaging.setup_person_keys(sender)
        
        try:
            # Encrypt the message using receiver's public key
            encrypted_body, metadata = RSAMessaging.encrypt_message(plaintext, receiver.public_key)
            
            # Create the encrypted message using core Message class
            message = Message(sender_id, receiver_id, encrypted_body, "rsa_encrypted", metadata)
            
            # Send through the network using core routing
            success = network.send_message(message)
            
            if success:
                print(f"✅ RSA encrypted message sent from {sender_id} to {receiver_id}")
                print(f"   Original length: {len(plaintext)} chars")
                print(f"   Encrypted length: {len(encrypted_body)} chars")
            else:
                print(f"❌ Failed to route message from {sender_id} to {receiver_id}")
            
            return success
            
        except Exception as e:
            print(f"❌ RSA encryption failed: {str(e)}")
            return False
    
    @staticmethod
    def decrypt_received_message(person: Person, message_index: int) -> str:
        """
        Decrypt a received RSA encrypted message for a person.
        
        Args:
            person: Person who received the message
            message_index: Index of the message in their inbox
            
        Returns:
            Decrypted plaintext message
            
        Raises:
            ValueError: If message doesn't exist, isn't RSA encrypted, or person has no private key
        """
        if message_index >= len(person.messages):
            raise ValueError(f"Message index {message_index} out of range (person has {len(person.messages)} messages)")
        
        message = person.messages[message_index]
        
        if message.message_type != "rsa_encrypted":
            raise ValueError(f"Message is type '{message.message_type}', not 'rsa_encrypted'")
        
        if not hasattr(person, 'private_key') or not person.private_key:
            raise ValueError(f"Person {person.name} has no private key for decryption")
        
        return RSAMessaging.decrypt_message(message.message_body, person.private_key)

# =============================================================================
# DEMONSTRATION AND TESTING
# =============================================================================

def demonstrate_rsa_system():
    """
    Comprehensive demonstration of RSA encrypted messaging.
    Shows integration with the core communication system.
    """
    print("RSA Encryption Module Demo")
    print("=" * 35)
    
    # Use the core communication system
    network = CommunicationNetwork()
    
    # Add people to network
    print("\n1. Setting up network...")
    alice = network.add_person("alice", "Alice")
    hatter = network.add_person("hatter", "Hatter")
    cheshire = network.add_person("cheshire", "Cheshire")
    
    # Create friendships: Alice ↔ Hatter ↔ Cheshire
    network.add_friendship("alice", "hatter")
    network.add_friendship("hatter", "cheshire")
    
    print("   Network created with Alice ↔ Hatter ↔ Cheshire")
    
    # Set up RSA keys
    print("\n2. Generating RSA keys...")
    RSAMessaging.setup_person_keys(alice)
    RSAMessaging.setup_person_keys(hatter)
    RSAMessaging.setup_person_keys(cheshire)
    
    print(f"   Alice public key: {alice.public_key}")
    print(f"   Cheshire public key: {cheshire.public_key}")
    
    # Test direct encrypted messaging
    print("\n3. Testing encrypted messaging...")
    
    success1 = RSAMessaging.send_encrypted_message(
        network, "alice", "hatter", 
        "Hello Hatter! This message is encrypted with your public key."
    )
    
    # Test multi-hop encrypted messaging
    success2 = RSAMessaging.send_encrypted_message(
        network, "alice", "cheshire",
        "Hi Cheshire! This secret message travels through Hatter but he can't read it!"
    )
    
    success3 = RSAMessaging.send_encrypted_message(
        network, "cheshire", "alice",
        "Thanks Alice! This encrypted reply comes back through the network."
    )
    
    # Test various message types
    print("\n4. Testing edge cases...")
    RSAMessaging.send_encrypted_message(network, "hatter", "alice", "Short msg!")
    RSAMessaging.send_encrypted_message(network, "alice", "hatter", "Special chars: @#$%^&*()")
    
    # Demonstrate message decryption
    print("\n5. Decrypting received messages...")
    
    # Alice's messages
    alice_messages = network.get_messages("alice")
    print(f"\nAlice has {len(alice_messages)} encrypted message(s):")
    for i, msg in enumerate(alice_messages):
        try:
            decrypted = RSAMessaging.decrypt_received_message(alice, i)
            print(f"   Message {i+1} from {msg.sender_id}: '{decrypted}'")
            print(f"   Route: {' → '.join(msg.route)}")
            print(f"   Original length: {msg.metadata.get('original_length')} chars")
        except Exception as e:
            print(f"   Failed to decrypt message {i+1}: {e}")
    
    # Hatter's messages
    hatter_messages = network.get_messages("hatter")
    print(f"\nHatter has {len(hatter_messages)} encrypted message(s):")
    for i, msg in enumerate(hatter_messages):
        try:
            decrypted = RSAMessaging.decrypt_received_message(hatter, i)
            print(f"   Message {i+1} from {msg.sender_id}: '{decrypted}'")
        except Exception as e:
            print(f"   Failed to decrypt message {i+1}: {e}")
    
    # Cheshire's messages  
    cheshire_messages = network.get_messages("cheshire")
    print(f"\nCheshire has {len(cheshire_messages)} encrypted message(s):")
    for i, msg in enumerate(cheshire_messages):
        try:
            decrypted = RSAMessaging.decrypt_received_message(cheshire, i)
            print(f"   Message {i+1} from {msg.sender_id}: '{decrypted}'")
        except Exception as e:
            print(f"   Failed to decrypt message {i+1}: {e}")
    
    # Security demonstration
    print(f"\n6. Security demonstration:")
    if alice_messages:
        print("   Raw encrypted message (unreadable without private key):")
        encrypted_sample = alice_messages[0].message_body
        print(f"   '{encrypted_sample[:60]}{'...' if len(encrypted_sample) > 60 else ''}'")
    
    print(f"\n✅ RSA Encryption Implementation Complete!")
    print(f"✅ Messages encrypted with receiver's public key")
    print(f"✅ Only receiver can decrypt with their private key") 
    print(f"✅ Supports multi-hop routing through friend network")
    print(f"✅ Proper metadata indicates RSA encryption")

def test_rsa_directly():
    """Test RSA encryption/decryption functions directly"""
    print("\nDirect RSA Function Testing")
    print("-" * 30)
    
    # Test key generation
    public_key, private_key = generate_rsa_keys()
    print(f"Generated keys: public={public_key}, private={private_key}")
    
    # Test messages
    test_messages = [
        "Hello World!",
        "X",
        "This is a longer test message with various characters.",
        "123 @#$%"
    ]
    
    for i, message in enumerate(test_messages):
        print(f"\nTest {i+1}: '{message}'")
        try:
            # Encrypt
            encrypted, metadata = RSAMessaging.encrypt_message(message, public_key)
            print(f"  Encrypted successfully (length: {len(encrypted)})")
            
            # Decrypt
            decrypted = RSAMessaging.decrypt_message(encrypted, private_key)
            print(f"  Decrypted: '{decrypted}'")
            print(f"  Match: {'✅' if message == decrypted else '❌'}")
            
        except Exception as e:
            print(f"  Error: {e}")

if __name__ == "__main__":
    # Run demonstrations when this file is executed directly
    demonstrate_rsa_system()
    test_rsa_directly()
