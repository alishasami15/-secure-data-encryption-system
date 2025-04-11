import streamlit as st
from cryptography.fernet import Fernet
import base64
import hashlib

# -------------------- HELPER FUNCTIONS --------------------

def generate_key(passkey):
    """Generate a Fernet key based on passkey."""
    key = hashlib.sha256(passkey.encode()).digest()
    return base64.urlsafe_b64encode(key)

def encrypt_message(message, passkey):
    key = generate_key(passkey)
    fernet = Fernet(key)
    return fernet.encrypt(message.encode()).decode()

def decrypt_message(token, passkey):
    try:
        key = generate_key(passkey)
        fernet = Fernet(key)
        return fernet.decrypt(token.encode()).decode()
    except Exception as e:
        return None

# -------------------- LOGIN SYSTEM --------------------

users = {
    "admin": "admin123",  # username: password
    "alisha": "exellent29"
}

failed_attempts = {}

def login(username, password):
    if username in users and users[username] == password:
        return True
    else:
        failed_attempts[username] = failed_attempts.get(username, 0) + 1
        return False

# -------------------- STREAMLIT UI --------------------

st.set_page_config(page_title="🔐 Secure Encryption App", layout="centered")

st.title("🔐 Secure Data Encryption System")
st.markdown("Made with ❤️ using Python & Streamlit")

# Sidebar login
st.sidebar.title("🔐 Login")
username = st.sidebar.text_input("Username")
password = st.sidebar.text_input("Password", type="password")
login_button = st.sidebar.button("Login")

if login_button:
    if login(username, password):
        st.success(f"Welcome, {username}!")
        option = st.selectbox("Choose Action", ["Encrypt Data", "Decrypt Data"])

        if option == "Encrypt Data":
            plain_text = st.text_area("Enter Text to Encrypt")
            passkey = st.text_input("Enter Passkey", type="password")
            if st.button("Encrypt"):
                if plain_text and passkey:
                    encrypted = encrypt_message(plain_text, passkey)
                    st.code(encrypted, language="text")
                else:
                    st.warning("Please enter both text and passkey.")

        elif option == "Decrypt Data":
            encrypted_text = st.text_area("Enter Encrypted Text")
            passkey = st.text_input("Enter Passkey", type="password")
            if st.button("Decrypt"):
                if encrypted_text and passkey:
                    decrypted = decrypt_message(encrypted_text, passkey)
                    if decrypted:
                        st.success("Decrypted Text:")
                        st.code(decrypted, language="text")
                    else:
                        st.error("Invalid passkey or encrypted text.")
                else:
                    st.warning("Please enter both encrypted text and passkey.")

    else:
        st.sidebar.error("Invalid credentials.")
        st.sidebar.warning(f"Failed Attempts: {failed_attempts.get(username, 0)}")
