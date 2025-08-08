"""
Core Communication System
ICS 311 Assignment 7

Author: Michaela Gillan

This module is:
Core data structures for the team's messaging system

The core structures can be used by other team members to implement
run-length encoding, FFT compression, digital signatures, etc.
"""

import json
import math
import random
import base64
from collections import deque
from typing import Dict, List, Tuple, Optional

# =============================================================================
# CORE DATA STRUCTURES (for team use)
# =============================================================================

class Person:
    """
    Core Person class representing a node in the friend network.
    All team members should use this structure.
    """
    
    def __init__(self, person_id: str, name: str):
        self.person_id = person_id
        self.name = name
        self.connections = set()  # Set of friend IDs
        self.messages = []  # List of received Message objects
        
        # RSA keys (only needed for RSA encryption feature)
        self.public_key = None
        self.private_key = None
    
    def add_friend(self, friend_id: str):
        """Add a bidirectional friend connection"""
        self.connections.add(friend_id)
    
    def add_message(self, message):
        """Add a received message to this person's inbox"""
        self.messages.append(message)

class Message:
    """
    Core Message class that all team members should use.
    Supports different message types and extensible metadata.
    """
    
    def __init__(self, sender_id: str, receiver_id: str, message_body: str, 
                 message_type: str = "plain", metadata: Dict = None):
        self.sender_id = sender_id
        self.receiver_id = receiver_id
        self.message_body = message_body  # The actual message content (may be encoded/encrypted)
        self.message_type = message_type  # e.g., "plain", "rsa_encrypted", "rle_compressed", "fft_compressed", "signed"
        self.metadata = metadata or {}    # Additional info about the message
        self.route = []  # Path the message took through the network
    
    def to_dict(self) -> Dict:
        """Convert message to dictionary for serialization/debugging"""
        return {
            'sender_id': self.sender_id,
            'receiver_id': self.receiver_id,
            'message_body': self.message_body,
            'message_type': self.message_type,
            'metadata': self.metadata,
            'route': self.route
        }

class CommunicationNetwork:
    """
    Core network class that manages the friend graph and message routing.
    All team members should use this same network structure.
    """
    
    def __init__(self):
        self.people = {}  # person_id -> Person object
    
    def add_person(self, person_id: str, name: str) -> Person:
        """Add a person to the network"""
        if person_id in self.people:
            raise ValueError(f"Person with ID '{person_id}' already exists")
        
        person = Person(person_id, name)
        self.people[person_id] = person
        return person
    
    def add_friendship(self, person1_id: str, person2_id: str):
        """Create a friendship between two people"""
        if person1_id not in self.people or person2_id not in self.people:
            raise ValueError("Both people must exist in the network")
        
        self.people[person1_id].add_friend(person2_id)
        self.people[person2_id].add_friend(person1_id)
    
    def find_path(self, sender_id: str, receiver_id: str) -> List[str]:
        """
        Find shortest path between sender and receiver using BFS.
        Returns list of person_ids representing the path.
        """
        if sender_id == receiver_id:
            return [sender_id]
        
        if sender_id not in self.people or receiver_id not in self.people:
            return []
        
        visited = set()
        queue = deque([(sender_id, [sender_id])])
        
        while queue:
            current_id, path = queue.popleft()
            
            if current_id in visited:
                continue
            visited.add(current_id)
            
            if current_id == receiver_id:
                return path
            
            # Explore all friends
            for friend_id in self.people[current_id].connections:
                if friend_id not in visited:
                    queue.append((friend_id, path + [friend_id]))
        
        return []  # No path found
    
    def send_message(self, message: Message) -> bool:
        """
        Route and deliver a message through the network.
        This is the core method that all message types use.
        """
        # Find path through network
        path = self.find_path(message.sender_id, message.receiver_id)
        if not path:
            return False
        
        # Set the route
        message.route = path
        
        # Deliver to receiver
        if message.receiver_id in self.people:
            self.people[message.receiver_id].add_message(message)
            return True
        
        return False
    
    def get_person(self, person_id: str) -> Optional[Person]:
        """Get a person from the network"""
        return self.people.get(person_id)
