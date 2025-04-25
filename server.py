import socket
import threading
import json
from crypto_utils import hash_password, verify_password
from crypto_utils import encrypt_message, derive_key, decrypt_message
import os
from message_logger import log_message, clear_log
from client import ChatClient

global self
key = derive_key("your_shared_secret")

class ChatServer:
    def __init__(self, host='localhost', port=5555):
        self.host = host
        self.client_keys = {}
        self.port = port
        self.key = derive_key("your_shared_secret")  
        clear_log()
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.clients = {}  
        self.users_db = 'users.json'
        self.load_users()

    def load_users(self):
        """Load users from JSON file or create empty database"""
        try:
            with open(self.users_db, 'r') as f:
                self.users = json.load(f)
        except FileNotFoundError:
            self.users = {}
            self.save_users()

    def save_users(self):
        """Save users to JSON file"""
        with open(self.users_db, 'w') as f:
            json.dump(self.users, f)

    def broadcast(self, message, sender_socket=None):
        """Send message to all clients except sender"""
        for client in self.clients:
            if client != sender_socket:
                try:
                    client.send(message.encode())
                except:
                    self.remove_client(client)

    def remove_client(self, client_socket):
        """Remove client from active clients"""
        if client_socket in self.clients:
            username = self.clients[client_socket]
            del self.clients[client_socket]
            self.broadcast(f"Server: {username} left the chat")
            client_socket.close()

    # In server.py
    def handle_client(self, client_socket, addr):
        """Handle individual client connection"""
        print(f"New connection from {addr}")
        
        while True:
            try:
                message = client_socket.recv(4096).decode()
                if not message:
                    break
    
                if message.startswith('/register'):
                    self.handle_registration(client_socket, message)
                elif message.startswith('/login'):
                    self.handle_login(client_socket, message)
                elif message.startswith('/quit'):
                    break
                else:
                    if client_socket in self.clients:
                        username = self.clients[client_socket]
                        try:
                            # Log the detailed format to file
                            #with open('message_log.txt', 'a') as log_file:
                                #log_file.write(f"{username} : {message}:\n")
                            
                            broadcast_message = f"{username}: {message}"
                            self.broadcast(broadcast_message, client_socket)
                        except Exception as e:
                            print(f"Error processing message: {e}")
                    else:
                        client_socket.send("Please login first".encode())
    
            except ConnectionResetError:
                print(f"Client {addr} disconnected unexpectedly")
                break
            except Exception as e:
                print(f"Error handling client {addr}: {e}")
                break
    
        self.remove_client(client_socket)
        print(f"Connection closed: {addr}")
    
    

    def handle_registration(self, client_socket, message):
        """Handle user registration"""
        try:
            _, username, password = message.split()
            if username in self.users:
                client_socket.send("/register_fail".encode())
                return

            salt, hash_value = hash_password(password)
            self.users[username] = {
                'salt': salt,
                'hash': hash_value
            }
            self.save_users()
            client_socket.send("/register_success".encode())

        except Exception as e:
            print(f"Registration error: {e}")
            client_socket.send("/register_fail".encode())

    def handle_login(self, client_socket, message):
        """Handle user login"""
        try:
            _, username, password = message.split()
            if username not in self.users:
                client_socket.send("/login_fail".encode())
                return

            user_data = self.users[username]
            if verify_password(password, user_data['salt'], user_data['hash']):
                self.clients[client_socket] = username
                client_socket.send("/login_success".encode())
                self.broadcast(f"Server: {username} joined the chat", client_socket)
            else:
                client_socket.send("/login_fail".encode())

        except Exception as e:
            print(f"Login error: {e}")
            client_socket.send("/login_fail".encode())

    def start(self):
        """Start the server"""
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"Server started on {self.host}:{self.port}")

        try:
            while True:
                client_socket, addr = self.server_socket.accept()
                print(f"New connection from {addr}")
                
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, addr)
                )
                client_thread.daemon = True
                client_thread.start()

        except KeyboardInterrupt:
            print("\nShutting down server...")
        finally:
            self.server_socket.close()

if __name__ == "__main__":
    server = ChatServer()
    server.start()
