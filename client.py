import tkinter as tk
from tkinter import messagebox, scrolledtext
import socket
import threading
from crypto_utils import encrypt_message, decrypt_message, derive_key
from message_logger import log_message, clear_log


global username
username = None

class ChatClient:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat")
        self.root.geometry("800x600")
        
        self.HOST = 'localhost'
        self.PORT = 5555
        self.connected = False
        self.key = None
        
        clear_log()
        self.setup_gui()
        self.connect_to_server()
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def connect_to_server(self):
        """Establish connection to the server with proper error handling"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.HOST, self.PORT))
            self.connected = True
            self.receive_thread = threading.Thread(target=self.receive_messages)
            self.receive_thread.daemon = True
            self.receive_thread.start()
        except ConnectionRefusedError:
            messagebox.showerror("Connection Error", 
                "Could not connect to server. Please ensure server is running.")
            self.connected = False
        except Exception as e:
            messagebox.showerror("Error", f"Connection error: {str(e)}")
            self.connected = False

    def setup_gui(self):
        # Login Frame
        self.login_frame = tk.Frame(self.root)
        self.login_frame.pack(pady=20)

        tk.Label(self.login_frame, text="Username:").grid(row=0, column=0, padx=5)
        self.entry_user = tk.Entry(self.login_frame)
        self.entry_user.grid(row=0, column=1, padx=5)

        tk.Label(self.login_frame, text="Password:").grid(row=1, column=0, padx=5)
        self.entry_pass = tk.Entry(self.login_frame, show="*")
        self.entry_pass.grid(row=1, column=1, padx=5)

        tk.Button(self.login_frame, text="Login", command=self.login).grid(row=2, column=0, pady=10)
        tk.Button(self.login_frame, text="Register", command=self.register).grid(row=2, column=1, pady=10)

        self.chat_frame = tk.Frame(self.root)
        
        self.text_area = scrolledtext.ScrolledText(self.chat_frame, wrap=tk.WORD, height=20)
        self.text_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        self.text_area.config(state='disabled')

        self.entry_msg = tk.Entry(self.chat_frame)
        self.entry_msg.pack(padx=10, fill=tk.X, side=tk.LEFT, expand=True)
        self.entry_msg.bind("<Return>", self.send_message)

        tk.Button(self.chat_frame, text="Send", command=self.send_message).pack(padx=10, side=tk.RIGHT)

    def login(self):
        global username
        username = self.entry_user.get().strip()
        if not self.connected:
            self.connect_to_server()
            if not self.connected:
                return

        #username = self.entry_user.get().strip()
        password = self.entry_pass.get().strip()
        
        if not username or not password:
            messagebox.showerror("Error", "Username and password cannot be empty")
            return

        try:
            self.sock.send(f"/login {username} {password}".encode())
            self.key = derive_key(password)
        except (BrokenPipeError, ConnectionResetError):
            messagebox.showerror("Connection Error", "Lost connection to server")
            self.connected = False
            self.connect_to_server()
        except Exception as e:
            messagebox.showerror("Error", f"Login error: {str(e)}")

    def register(self):
        if not self.connected:
            self.connect_to_server()
            if not self.connected:
                return

        username = self.entry_user.get().strip()
        password = self.entry_pass.get().strip()
        
        if not username or not password:
            messagebox.showerror("Error", "Username and password cannot be empty")
            return
        
        if len(password) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters long")
            return

        try:
            self.sock.send(f"/register {username} {password}".encode())
            self.key = derive_key(password)
        except (BrokenPipeError, ConnectionResetError):
            messagebox.showerror("Connection Error", "Lost connection to server")
            self.connected = False
            self.connect_to_server()
        except Exception as e:
            messagebox.showerror("Error", f"Registration error: {str(e)}")

    def send_message(self, event=None):
        """Handle sending messages with proper formatting and encryption"""
        if not self.connected:
            messagebox.showerror("Error", "Not connected to server")
            return

        msg = self.entry_msg.get().strip()
        if not msg:
         return
        
        if len(msg) > 1000:
            messagebox.showwarning("Warning", "Message too long (max 1000 characters)")
            return
        
        try:
        # Encrypt the message
            if self.key is None:
                messagebox.showerror("Error", "Encryption key is not initialized")
                return
            encrypted = encrypt_message(self.key, msg)

            self.sock.send(encrypted.encode())
            self.entry_msg.delete(0, tk.END)

            self.display_message(f"{username}: {msg}")
        
        # Log the detailed format to file
            with open('message_log.txt', 'a') as log_file:
                log_file.write(f"{username} : {msg} : {encrypted}\n")
        
        except (BrokenPipeError, ConnectionResetError):
            messagebox.showerror("Connection Error", "Lost connection to server")
            self.connected = False
            #self.attempt_reconnect() # type: ignore
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send message: {str(e)}")

    def display_message(self, message):
        """Display message in the text area"""
        self.text_area.config(state='normal')
        self.text_area.insert(tk.END, message + "\n")
        self.text_area.config(state='disabled')
        self.text_area.see(tk.END)



    def receive_messages(self):
        while self.connected:
            try:
                data = self.sock.recv(4096).decode()
                if not data:
                    self.display_message("Disconnected from server")
                    self.connected = False
                    break
                
                if data.startswith("/login_success"):
                    self.login_frame.pack_forget()
                    self.chat_frame.pack(fill=tk.BOTH, expand=True)
                elif data.startswith("/login_fail"):
                    messagebox.showerror("Error", "Login failed")
                elif data.startswith("/register_success"):
                    messagebox.showinfo("Success", "Registration successful")
                elif data.startswith("/register_fail"):
                    messagebox.showerror("Error", "Registration failed")
                else:
                    try:
                        decrypted = decrypt_message(self.key, data) # type: ignore
                        self.display_message(decrypted)
                    except Exception as e:
                        self.display_message(f"Error decrypting message: {str(e)}")
            except (ConnectionResetError, BrokenPipeError):
                self.display_message("Lost connection to server")
                self.connected = False
                break
            except Exception as e:
                self.display_message(f"Error: {str(e)}")
                break

    

    def on_closing(self):
        clear_log()
        if self.connected:
            try:
                self.sock.send("/quit".encode())
                self.sock.close()
            except:
                pass
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    client = ChatClient(root)
    root.mainloop()
