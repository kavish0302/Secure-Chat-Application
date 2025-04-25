
# 🔐 SafeChat - A Secure Messaging App Using Real Cryptography

> Ever wondered how encrypted messaging actually works?  
> **SafeChat** is a secure terminal-based chat application that puts cryptographic theory into *practical use*, built as part of my Applied Cryptography Lab project.

---

## 💡 Overview

SafeChat is a Python-based messaging system that lets users exchange encrypted messages using AES-256. It also includes secure user authentication using PBKDF2 with HMAC-SHA256 and a JSON-based user store.

This project was developed by **Kavish Gulati** under the guidance of **Dr. Gururaj H L**, for partial fulfillment of the **Applied Cryptography Lab**.

---

## 🔐 Features

- **End-to-End AES-256 Encryption**
  - Messages are encrypted with a user-defined key before being sent.
  - Uses CBC mode with PKCS7 padding for secure message blocks.
        
- **Secure User Authentication**
  - Passwords are never stored in plaintext.
  - Implements PBKDF2 hashing with per-user salts.

- **Encrypted Logging**
  - Messages are logged in both plaintext and encrypted formats for educational use.
  - The logs are securely deleted when the app is restarted or closed.

- **Modular Design**
  - All cryptographic operations are abstracted into a utility module for easy understanding and reuse.

---

## 🛠️ Tech Stack

- **Language:** Python 3
- **Encryption:** AES-256 (CBC)
- **Hashing:** PBKDF2-HMAC-SHA256
- **Data Storage:** JSON
- **UI:** Command-Line Interface (CLI)

---

## 🚀 How It Works

### Download the requirements
```bash
pip install -r requirements.txt
```

### 1. Register / Login
Users register with a username and password. Passwords are hashed and salted using PBKDF2 and stored securely.

### 2. Start Server
Launch the server:
```bash
python server.py
```

### 3. Connect Clients
Run the client app and log in:
```bash
python client.py
```

Each message typed is encrypted on the sender's side and decrypted on the receiver's end—using the same key derived from the login session.

---

## 📦 Project Structure

```
├── client.py           # Handles user input and message sending/receiving
├── server.py           # Manages multiple client connections
├── crypto_utils.py     # Encryption, decryption, and hashing functions
├── message_logger.py   # Handles encrypted logging and deletion
├── users.json          # Stores user credentials securely (hashed + salted)
```

---

## 🌱 Future Plans

- Add a Tkinter or PyQt GUI
- Integrate secure key exchange (e.g., Diffie-Hellman)
- QR code-based login/authentication
- TLS/SSL-based encrypted socket connections

---

## 🙌 Acknowledgments

Built with lots of late-night debugging and coffee by **Kavish Gulati**,  
under the supervision of **Dr. Gururaj H L**.

---

## 📜 License

This project is open-source for learning purposes. Contributions and suggestions are welcome!

---

## 🔗 Let's Connect

Feel free to connect with me on [LinkedIn](#) or contribute to the repo!
