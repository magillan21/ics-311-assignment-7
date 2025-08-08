"""
Core Communication System Data Structures
Assignment 7 (Group 8)

This module contains the shared data structures for the team.
It provides the foundation for the friend network graph and message routing system.

Team members should import this module and use these classes for consistency:
- Person: Represents people in the friend network
- Message: Standardized message format for all communication types  
- CommunicationNetwork: Manages the graph and routes messages
"""

from collections import deque
from typing import Dict, List, Optional

class Person:
    """
    Represents a person/node in the friend network.
    
    Use this exact class structure for consistency.
    You can add additional attributes needed for your specific message type
    (e.g., RSA keys, compression settings, etc.) but don't change the core structure.
    """
    
    def __init__(self, person_id: str, name: str):
        """
        Initialize a person in the network.
        """
        self.person_id = person_id
        self.name = name
        self.connections = set()  # Set of friend person_ids
        self.messages = []  # List of received Message objects
        
        # Additional attributes can be added by team members for their features:
        # e.g., self.public_key = None (for RSA)
        # e.g., self.compression_settings = {} (for FFT)
        # etc.
    
    def add_friend(self, friend_id: str):
        """Add a friend connection (one-way)"""
        self.connections.add(friend_id)
    
    def add_message(self, message):
        """Add a received message to this person's inbox"""
        self.messages.append(message)
    
    def __str__(self):
        return f"Person({self.person_id}: {self.name})"
    
    def __repr__(self):
        return self.__str__()

class Message:
    """
    Standardized message format for ALL communication types.
    
    Use this exact message structure. The message_type field
    should indicate what kind of processing was done to the message_body.
    
    Supported message_type values (add yours here):
    - "plain": Unprocessed message
    - "rsa_encrypted": RSA encrypted message
    - "rle_compressed": Run-length encoded message  
    - "fft_compressed": FFT lossy compressed message
    - "signed": Digitally signed message
    - "receipt_confirmation": Signed receipt confirmation
    """
    
    def __init__(self, sender_id: str, receiver_id: str, message_body: str, 
                 message_type: str = "plain", metadata: Dict = None):
        """
        Create a message.
        
        Args:
            sender_id: ID of the person sending the message
            receiver_id: ID of the intended recipient
            message_body: The actual message content (may be encoded/encrypted)
            message_type: Type of processing applied to the message
            metadata: Additional information about the message processing
        """
        self.sender_id = sender_id
        self.receiver_id = receiver_id
        self.message_body = message_body
        self.message_type = message_type
        self.metadata = metadata or {}
        self.route = []  # Will be filled in by the network during routing
    
    def to_dict(self) -> Dict:
        """Convert message to dictionary (for debugging)"""
        return {
            'sender_id': self.sender_id,
            'receiver_id': self.receiver_id,
            'message_body': self.message_body,
            'message_type': self.message_type,
            'metadata': self.metadata,
            'route': self.route
        }
    
    def __str__(self):
        return f"Message({self.sender_id} → {self.receiver_id}, type: {self.message_type})"
    
    def __repr__(self):
        return self.__str__()

class CommunicationNetwork:
    """
    Manages the friend network graph and handles message routing.
    
    Use this class to manage the network. It handles:
    - Adding people to the network
    - Creating friendships (bidirectional connections)
    - Finding paths between people (BFS shortest path)
    - Routing messages through the network
    
    This class routes Message objects without caring about their content or processing.
    """
    
    def __init__(self):
        """Initialize an empty communication network"""
        self.people = {}  # person_id -> Person object
    
    def add_person(self, person_id: str, name: str) -> Person:
        """
        Add a person to the network.
        
        Args:
            person_id: Unique identifier for the person
            name: readable name
            
        Returns:
            Person object that was created and added
            
        Raises:
            ValueError: If person_id already exists
        """
        if person_id in self.people:
            raise ValueError(f"Person with ID '{person_id}' already exists")
        
        person = Person(person_id, name)
        self.people[person_id] = person
        return person
    
    def add_friendship(self, person1_id: str, person2_id: str):
        """
        Create a friendship between two people.
        
        Args:
            person1_id: ID of first person
            person2_id: ID of second person
            
        Raises:
            ValueError: If either person doesn't exist in the network
        """
        if person1_id not in self.people or person2_id not in self.people:
            raise ValueError("Both people must exist in the network before creating friendship")
        
        self.people[person1_id].add_friend(person2_id)
        self.people[person2_id].add_friend(person1_id)
    
    def find_path(self, sender_id: str, receiver_id: str) -> List[str]:
        """
        Find the shortest path between sender and receiver using BFS.
        
        This implements the requirement that "The sender does not need to be
        connected to the receiver" so messages can travel through intermediate friends.
        
        Args:
            sender_id: ID of message sender
            receiver_id: ID of message receiver
            
        Returns:
            List of person_ids representing the shortest path from sender to receiver.
            Returns empty list if no path exists.
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
            
            # Explore all friends of current person
            if current_id in self.people:
                for friend_id in self.people[current_id].connections:
                    if friend_id not in visited:
                        queue.append((friend_id, path + [friend_id]))
        
        return []  # No path found
    
    def send_message(self, message: Message) -> bool:
        """
        Route and deliver a message through the network.
        
        This is the core method that ALL message types use. It:
        1. Finds a path from sender to receiver
        2. Records the path in the message
        3. Delivers the message to the receiver's inbox
        
        Args:
            message: Message object to send
            
        Returns:
            True if message was successfully delivered, False otherwise
        """
        # Find path through the friend network
        path = self.find_path(message.sender_id, message.receiver_id)
        if not path:
            return False  # No path exists
        
        # Record the route the message took
        message.route = path
        
        # Deliver message to receiver's inbox
        if message.receiver_id in self.people:
            self.people[message.receiver_id].add_message(message)
            return True
        
        return False
    
    def get_person(self, person_id: str) -> Optional[Person]:
        """
        Get a person from the network.
        
        Args:
            person_id: ID of the person to retrieve
            
        Returns:
            Person object if found, None otherwise
        """
        return self.people.get(person_id)
    
    def get_messages(self, person_id: str) -> List[Message]:
        """
        Get all messages for a specific person.
        
        Args:
            person_id: ID of the person whose messages to retrieve
            
        Returns:
            List of Message objects (empty list if person not found)
        """
        person = self.get_person(person_id)
        return person.messages if person else []
    
    def print_network_status(self):
        """Print a summary of the current network state (useful for debugging)"""
        print(f"\n=== Network Status ===")
        print(f"Total people: {len(self.people)}")
        
        for person_id, person in self.people.items():
            print(f"\n{person.name} ({person_id}):")
            print(f"  Friends: {list(person.connections)}")
            print(f"  Messages received: {len(person.messages)}")

def create_sample_network() -> CommunicationNetwork:
    """
    Create a sample network for testing and demonstration.
    Team members can use this for testing their implementations.
    
    Returns:
        CommunicationNetwork with sample people and friendships
    """
    network = CommunicationNetwork()
    
    # Add people
    riddle= network.add_person("riddle", "Riddle")
    leona = network.add_person("leona", "Leona")
    azul = network.add_person("azul", "Azul")
    vil = network.add_person("vil", "Vil")
    
    # Create friendship chain: Riddle ↔ Leona ↔ Azul ↔ Vil
    network.add_friendship("riddle", "leona")
    network.add_friendship("leona", "azul")  
    network.add_friendship("azul", "vil")
    
    # Add one cross-connection: Riddle ↔ Azul
    network.add_friendship("riddle", "azul")
    
    return network

def test_core_system():
    """Test the core communication system"""
    print("Testing Core Communication System")
    print("=" * 40)
    
    # Create network
    network = create_sample_network()
    network.print_network_status()
    
    # Test basic messaging
    print(f"\nTesting basic message routing...")
    
    # Direct message (Riddle → Leona)
    msg1 = Message("riddle", "leona", "Hello Leona!", "plain")
    success1 = network.send_message(msg1)
    print(f"  Riddle → Leona: {'✅' if success1 else '❌'}")
    
    # Multi-hop message (Riddle → Vil, should go through Azul)
    msg2 = Message("riddle", "vil", "Hi Vil from Riddle!", "plain") 
    success2 = network.send_message(msg2)
    print(f"  Riddle → Vil: {'✅' if success2 else '❌'}")
    
    # Check message delivery
    print(f"\nMessage delivery results:")
    leona_messages = network.get_messages("leona")
    vil_messages = network.get_messages("vil")
    
    print(f"  Leona received {len(leona_messages)} message(s)")
    if leona_messages:
        print(f"    Message: '{leona_messages[0].message_body}'")
        print(f"    Route: {' → '.join(leona_messages[0].route)}")
    
    print(f"  Vil received {len(vil_messages)} message(s)")
    if vil_messages:
        print(f"    Message: '{vil_messages[0].message_body}'")
        print(f"    Route: {' → '.join(vil_messages[0].route)}")
    
    print(f"\n✅ Core system test complete!")
    return network

if __name__ == "__main__":
    # Run tests when this file is executed directly
    test_core_system()
