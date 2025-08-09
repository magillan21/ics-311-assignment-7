import numpy as np
from core_communication import CommunicationNetwork, Message

class FFTMessaging:
    """
    FFT-based lossy compression for messages.
    """
    
    @staticmethod
    def compress_message(message: str, lossiness: float = 0.5) -> (str, dict):
        # Change each letter to its number (ASCII)
        arr = np.array([ord(c) for c in message], dtype=float)
        
        # FFT
        fft_coeffs = np.fft.fft(arr)
        
        # Keep only biggest parts based on lossiness
        n = len(fft_coeffs)
        keep = max(1, int(n * (1 - lossiness)))  # at least keep 1
        
    
        sorted_positions = np.argsort(np.abs(fft_coeffs))
        for position in sorted_positions[:n - keep]:
            fft_coeffs[position] = 0
        
        # Convert back to normal data and limit to readable chars
        compressed_arr = np.fft.ifft(fft_coeffs).real
        compressed_arr = np.clip(np.round(compressed_arr), 32, 126)
        
        # Change numbers back to letters
        compressed_message = ""
        for number in compressed_arr:
            character = chr(int(number))
            compressed_message += character
        
        metadata = {
            "compression": "fft",
            "original_length": len(message),
            "lossiness": lossiness
        }
        
        return compressed_message, metadata
    
    @staticmethod
    def send_compressed_message(network: CommunicationNetwork, sender_id: str, receiver_id: str, message: str, lossiness: float = 0.5) -> bool:
        compressed_text, info = FFTMessaging.compress_message(message, lossiness)
        new_message = Message(sender_id, receiver_id, compressed_text, "fft_compressed", info)
        return network.send_message(new_message)
    
    @staticmethod
    def decompress_message(message: Message) -> str:
        if message.message_type != "fft_compressed":
            return "Message is not FFT compressed"
        return message.message_body

# Example test
def test_fft_compression():
    network = CommunicationNetwork()
    network.add_person("alice", "Alice")
    network.add_person("bob", "Bob")
    network.add_friendship("alice", "bob")
    
    original = "Hello Wonderland!"

    print(f"Original: {original}")
    
    FFTMessaging.send_compressed_message(network, "alice", "bob", original, lossiness=0.5)
    
    bob_msgs = network.get_messages("bob")
    if bob_msgs:
        print(f"Compressed message sent: {bob_msgs[0].message_body}")
        print(f"Metadata: {bob_msgs[0].metadata}")

if __name__ == "__main__":
    test_fft_compression()
