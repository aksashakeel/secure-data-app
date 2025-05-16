import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Generate a key (normally you'd store this securely)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# In-memory data store
stored_data = {}  # {encrypted_text: {"encrypted_text": ..., "passkey": ...}}
failed_attempts = 0

# Hash the passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decrypt data
def decrypt_data(encrypted_text, passkey):
    global failed_attempts
    hashed_passkey = hash_passkey(passkey)

    data = stored_data.get(encrypted_text)
    if data and data["passkey"] == hashed_passkey:
        failed_attempts = 0
        return cipher.decrypt(encrypted_text.encode()).decode()
    else:
        failed_attempts += 1
        return None

# Streamlit UI
st.set_page_config(page_title="🔐 Secure Data App")
st.title("🔐 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Menu", menu)

if "reauthorized" not in st.session_state:
    st.session_state.reauthorized = False

if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("This app allows you to store and retrieve encrypted data using a secure passkey.")

elif choice == "Store Data":
    st.subheader("📁 Store Your Data")
    user_data = st.text_area("Enter Data")
    passkey = st.text_input("Enter Passkey", type="password")

    if st.button("Encrypt & Store"):
        if user_data and passkey:
            hashed = hash_passkey(passkey)
            encrypted = encrypt_data(user_data)
            stored_data[encrypted] = {"encrypted_text": encrypted, "passkey": hashed}
            st.success("✅ Data encrypted and stored!")
            st.code(encrypted, language='text')
        else:
            st.error("⚠️ Please fill both fields!")

elif choice == "Retrieve Data":
    st.subheader("🔎 Retrieve Your Data")
    encrypted_text = st.text_area("Enter Encrypted Text")
    passkey = st.text_input("Enter Passkey", type="password")

    if failed_attempts >= 3 and not st.session_state.reauthorized:
        st.warning("🔒 Too many failed attempts. Redirecting to login...")
        st.experimental_rerun()

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            result = decrypt_data(encrypted_text, passkey)
            if result:
                st.success("✅ Decrypted Data")
                st.code(result, language='text')
            else:
                remaining = max(0, 3 - failed_attempts)
                st.error(f"❌ Incorrect passkey! Attempts remaining: {remaining}")
        else:
            st.error("⚠️ Please provide both encrypted data and passkey!")

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    master_key = st.text_input("Enter Admin Password", type="password")

    if st.button("Login"):
        if master_key == "admin123":
            failed_attempts = 0
            st.session_state.reauthorized = True
            st.success("✅ Login successful! You may now try retrieving data again.")
        else:
            st.error("❌ Incorrect admin password")
