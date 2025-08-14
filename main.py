import streamlit as st
import json
import sqlite3
import zlib
import lzma
import hashlib
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pandas as pd
import time
from datetime import datetime
import secrets
import string

# Page configuration
st.set_page_config(
    page_title="Secure Password Vault",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'master_key' not in st.session_state:
    st.session_state.master_key = None
if 'compression_stats' not in st.session_state:
    st.session_state.compression_stats = []
if 'generated_password' not in st.session_state:
    st.session_state.generated_password = ""
if 'visible_passwords' not in st.session_state:
    st.session_state.visible_passwords = set()


class PasswordVault:
    def __init__(self, db_path="password_vault.db"):
        self.db_path = db_path
        self.init_database()

    def init_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
                       CREATE TABLE IF NOT EXISTS vault_config
                       (
                           id
                           INTEGER
                           PRIMARY
                           KEY,
                           salt
                           BLOB,
                           master_hash
                           TEXT
                       )
                       ''')

        cursor.execute('''
                       CREATE TABLE IF NOT EXISTS passwords
                       (
                           id
                           INTEGER
                           PRIMARY
                           KEY
                           AUTOINCREMENT,
                           service_name
                           TEXT
                           NOT
                           NULL,
                           username
                           TEXT,
                           encrypted_data
                           BLOB,
                           compression_method
                           TEXT,
                           original_size
                           INTEGER,
                           compressed_size
                           INTEGER,
                           created_at
                           TIMESTAMP
                           DEFAULT
                           CURRENT_TIMESTAMP,
                           updated_at
                           TIMESTAMP
                           DEFAULT
                           CURRENT_TIMESTAMP
                       )
                       ''')

        conn.commit()
        conn.close()

    def generate_key_from_password(self, master_password, salt):
        """Generate encryption key from master password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        return key

    def set_master_password(self, master_password):
        """Set master password for the vault"""
        salt = os.urandom(16)
        key = self.generate_key_from_password(master_password, salt)
        master_hash = hashlib.sha256(master_password.encode()).hexdigest()

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM vault_config")
        cursor.execute(
            "INSERT INTO vault_config (salt, master_hash) VALUES (?, ?)",
            (salt, master_hash)
        )
        conn.commit()
        conn.close()
        return key

    def verify_master_password(self, master_password):
        """Verify master password and return encryption key"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT salt, master_hash FROM vault_config LIMIT 1")
        result = cursor.fetchone()
        conn.close()

        if not result:
            return None

        salt, stored_hash = result
        master_hash = hashlib.sha256(master_password.encode()).hexdigest()

        if master_hash == stored_hash:
            return self.generate_key_from_password(master_password, salt)
        return None

    def compress_data(self, data, method="lzma"):
        """Compress data using specified method"""
        data_bytes = json.dumps(data).encode('utf-8')
        original_size = len(data_bytes)

        entropy = self.calculate_entropy(data_bytes)
        start_time = time.time()

        try:
            if method == "lzma":
                compressed = lzma.compress(data_bytes, preset=6)
            elif method == "zlib":
                compressed = zlib.compress(data_bytes, level=9)
            elif method == "huffman":
                # Fixed Huffman compression - using compressobj for strategy support
                compressor = zlib.compressobj(level=9, strategy=zlib.Z_HUFFMAN_ONLY)
                compressed = compressor.compress(data_bytes) + compressor.flush()
            elif method == "none":
                compressed = data_bytes
            else:
                # Default to lzma if unknown method
                compressed = lzma.compress(data_bytes, preset=6)
                method = "lzma"
        except Exception as e:
            st.error(f"Compression error with {method}: {str(e)}")
            # Fallback to no compression
            compressed = data_bytes
            method = "none"

        compression_time = time.time() - start_time
        compressed_size = len(compressed)
        compression_ratio = (1 - compressed_size / original_size) * 100 if original_size > 0 else 0

        return compressed, original_size, compressed_size, compression_ratio, method, entropy, compression_time

    def calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0

        frequency = {}
        for byte in data:
            frequency[byte] = frequency.get(byte, 0) + 1

        entropy = 0
        data_len = len(data)
        for count in frequency.values():
            probability = count / data_len
            if probability > 0:
                import math
                entropy -= probability * math.log2(probability)

        return entropy

    def decompress_data(self, compressed_data, method):
        """Decompress data using specified method"""
        try:
            if method == "lzma":
                decompressed = lzma.decompress(compressed_data)
            elif method == "zlib":
                decompressed = zlib.decompress(compressed_data)
            elif method == "huffman":
                # Fixed Huffman decompression - standard zlib decompress works for huffman
                decompressed = zlib.decompress(compressed_data)
            elif method == "none":
                decompressed = compressed_data
            else:
                # Try lzma as default
                decompressed = lzma.decompress(compressed_data)
        except Exception as e:
            st.error(f"Decompression error with {method}: {str(e)}")
            return None

        try:
            return json.loads(decompressed.decode('utf-8'))
        except Exception as e:
            st.error(f"JSON parsing error: {str(e)}")
            return None

    def store_password(self, service_name, username, password, notes="", compression_method="lzma"):
        """Store encrypted and compressed password"""
        if not st.session_state.master_key:
            return False, "No master key available"

        password_data = {
            "password": password,
            "notes": notes,
            "created_at": datetime.now().isoformat()
        }

        try:
            compressed_data, orig_size, comp_size, comp_ratio, method, entropy, comp_time = self.compress_data(
                password_data, compression_method
            )

            fernet = Fernet(st.session_state.master_key)
            encrypted_data = fernet.encrypt(compressed_data)

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                           INSERT INTO passwords
                           (service_name, username, encrypted_data, compression_method, original_size, compressed_size)
                           VALUES (?, ?, ?, ?, ?, ?)
                           ''', (service_name, username, encrypted_data, method, orig_size, comp_size))
            conn.commit()
            conn.close()

            st.session_state.compression_stats.append({
                "method": method,
                "original_size": orig_size,
                "compressed_size": comp_size,
                "ratio": comp_ratio,
                "entropy": entropy,
                "time": comp_time,
                "service": service_name
            })

            return True, f"Password stored successfully! Compression: {comp_ratio:.1f}% using {method}"

        except Exception as e:
            return False, f"Error storing password: {str(e)}"

    def get_all_passwords(self):
        """Retrieve and decrypt all passwords"""
        if not st.session_state.master_key:
            return []

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
                       SELECT id,
                              service_name,
                              username,
                              encrypted_data,
                              compression_method,
                              original_size,
                              compressed_size,
                              created_at,
                              updated_at
                       FROM passwords
                       ORDER BY service_name
                       ''')
        results = cursor.fetchall()
        conn.close()

        passwords = []
        fernet = Fernet(st.session_state.master_key)

        for row in results:
            try:
                encrypted_data = row[3]
                decrypted_data = fernet.decrypt(encrypted_data)
                password_data = self.decompress_data(decrypted_data, row[4])

                if password_data is not None:
                    passwords.append({
                        "id": row[0],
                        "service_name": row[1],
                        "username": row[2],
                        "password": password_data["password"],
                        "notes": password_data.get("notes", ""),
                        "compression_method": row[4],
                        "original_size": row[5],
                        "compressed_size": row[6],
                        "compression_ratio": (1 - row[6] / row[5]) * 100 if row[5] > 0 else 0,
                        "created_at": row[7],
                        "updated_at": row[8]
                    })
            except Exception as e:
                st.error(f"Error decrypting password for {row[1]}: {str(e)}")

        return passwords

    def delete_password(self, password_id):
        """Delete a password entry"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM passwords WHERE id = ?", (password_id,))
        conn.commit()
        conn.close()
        return True

    def has_master_password(self):
        """Check if master password is set"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM vault_config")
        count = cursor.fetchone()[0]
        conn.close()
        return count > 0


def generate_password(length=16, include_symbols=True, include_numbers=True, include_uppercase=True):
    """Generate a secure random password"""
    characters = string.ascii_lowercase
    if include_uppercase:
        characters += string.ascii_uppercase
    if include_numbers:
        characters += string.digits
    if include_symbols:
        characters += "!@#$%^&*()_+-=[]{}|;:,.<>?"

    password = ''.join(secrets.choice(characters) for _ in range(length))
    return password


def check_password_strength(password):
    """Check password strength and return score and feedback"""
    score = 0
    feedback = []

    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("Use at least 8 characters (12+ recommended)")

    if any(c.islower() for c in password):
        score += 1
    else:
        feedback.append("Include lowercase letters")

    if any(c.isupper() for c in password):
        score += 1
    else:
        feedback.append("Include uppercase letters")

    if any(c.isdigit() for c in password):
        score += 1
    else:
        feedback.append("Include numbers")

    if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        score += 2
    else:
        feedback.append("Include special characters")

    if len(password) >= 16:
        score += 1

    strength_levels = {
        0: ("Very Weak", "🔴"), 1: ("Very Weak", "🔴"), 2: ("Weak", "🟠"),
        3: ("Fair", "🟡"), 4: ("Good", "🟢"), 5: ("Strong", "🟢"),
        6: ("Very Strong", "🔵"), 7: ("Excellent", "🟣"), 8: ("Excellent", "🟣")
    }

    strength, emoji = strength_levels.get(min(score, 8), ("Unknown", "❓"))
    return score, strength, emoji, feedback


def main():
    vault = PasswordVault()

    st.title("🔐 Secure Password Vault")
    st.markdown("*Advanced Data Compression & Encryption Project*")

    st.sidebar.title("Navigation")

    if not st.session_state.logged_in:
        st.header("🔑 Authentication")

        if not vault.has_master_password():
            st.subheader("Setup Master Password")
            st.info("This is your first time using the vault. Please set up a master password.")

            with st.form("setup_master"):
                master_password = st.text_input("Create Master Password", type="password")
                confirm_password = st.text_input("Confirm Master Password", type="password")
                submit = st.form_submit_button("Create Vault")

                if submit:
                    if not master_password:
                        st.error("Master password cannot be empty")
                    elif master_password != confirm_password:
                        st.error("Passwords do not match")
                    elif len(master_password) < 8:
                        st.error("Master password must be at least 8 characters long")
                    else:
                        key = vault.set_master_password(master_password)
                        st.session_state.master_key = key
                        st.session_state.logged_in = True
                        st.success("Vault created successfully!")
                        st.rerun()
        else:
            st.subheader("Login to Vault")

            with st.form("login"):
                master_password = st.text_input("Master Password", type="password")
                submit = st.form_submit_button("Login")

                if submit:
                    key = vault.verify_master_password(master_password)
                    if key:
                        st.session_state.master_key = key
                        st.session_state.logged_in = True
                        st.success("Login successful!")
                        st.rerun()
                    else:
                        st.error("Invalid master password")
    else:
        menu = st.sidebar.selectbox(
            "Choose Function",
            ["🏠 Dashboard", "➕ Add Password", "📋 View Passwords", "📊 Analytics", "🔧 Tools", "🚪 Logout"]
        )

        if menu == "🏠 Dashboard":
            st.header("📊 Dashboard")

            passwords = vault.get_all_passwords()

            col1, col2, col3, col4 = st.columns(4)

            with col1:
                st.metric("Total Passwords", len(passwords))

            with col2:
                if passwords:
                    total_original = sum(p['original_size'] for p in passwords)
                    total_compressed = sum(p['compressed_size'] for p in passwords)
                    avg_compression = (1 - total_compressed / total_original) * 100 if total_original > 0 else 0
                    st.metric("Avg Compression", f"{avg_compression:.1f}%")
                else:
                    st.metric("Avg Compression", "0%")

            with col3:
                if passwords:
                    total_saved = sum(p['original_size'] - p['compressed_size'] for p in passwords)
                    st.metric("Space Saved", f"{total_saved} bytes")
                else:
                    st.metric("Space Saved", "0 bytes")

            with col4:
                methods = [p['compression_method'] for p in passwords]
                most_used = max(set(methods), key=methods.count) if methods else "None"
                st.metric("Most Used Method", most_used)

            if passwords:
                st.subheader("Recent Passwords")
                recent_df = pd.DataFrame(passwords[:5])
                st.dataframe(
                    recent_df[['service_name', 'username', 'compression_method', 'compression_ratio']],
                    use_container_width=True
                )

        elif menu == "➕ Add Password":
            st.header("➕ Add New Password")

            # Password generator section
            st.subheader("🎲 Password Generator")
            col1, col2 = st.columns(2)

            with col1:
                gen_length = st.slider("Length", 8, 32, 16)
                gen_symbols = st.checkbox("Include Symbols", value=True)

            with col2:
                gen_numbers = st.checkbox("Include Numbers", value=True)
                gen_uppercase = st.checkbox("Include Uppercase", value=True)

            if st.button("🎲 Generate New Password"):
                st.session_state.generated_password = generate_password(gen_length, gen_symbols, gen_numbers,
                                                                        gen_uppercase)

            if st.session_state.generated_password:
                st.code(st.session_state.generated_password)
                score, strength, emoji, feedback = check_password_strength(st.session_state.generated_password)
                st.write(f"Strength: {emoji} {strength}")

            st.divider()

            # Main form
            with st.form("add_password"):
                st.subheader("Password Entry")

                col1, col2 = st.columns(2)

                with col1:
                    service_name = st.text_input("Service/Website Name *")
                    username = st.text_input("Username/Email")

                with col2:
                    compression_method = st.selectbox(
                        "Compression Method",
                        ["lzma", "zlib", "huffman", "none"],
                        help="Choose compression algorithm: LZMA (best ratio), ZLIB (balanced), Huffman (fast), None (no compression)"
                    )

                password = st.text_input("Password *", type="password", value=st.session_state.generated_password)

                if password:
                    score, strength, emoji, feedback = check_password_strength(password)
                    st.write(f"Password Strength: {emoji} {strength}")

                notes = st.text_area("Notes (Optional)")

                submit = st.form_submit_button("💾 Save Password", type="primary")

                if submit:
                    if not service_name or not password:
                        st.error("Service name and password are required!")
                    else:
                        success, message = vault.store_password(
                            service_name, username, password, notes, compression_method
                        )
                        if success:
                            st.success(message)
                            # Clear generated password after successful save
                            st.session_state.generated_password = ""
                        else:
                            st.error(message)

        elif menu == "📋 View Passwords":
            st.header("📋 Stored Passwords")

            passwords = vault.get_all_passwords()

            if not passwords:
                st.info("No passwords stored yet. Add your first password!")
            else:
                search_term = st.text_input("🔍 Search passwords")

                filtered_passwords = passwords
                if search_term:
                    filtered_passwords = [
                        p for p in passwords
                        if search_term.lower() in p['service_name'].lower() or
                           search_term.lower() in (p['username'] or "").lower()
                    ]

                st.write(f"Showing {len(filtered_passwords)} passwords")

                for pwd in filtered_passwords:
                    with st.expander(f"🔐 {pwd['service_name']} ({pwd['username'] or 'No username'})"):
                        col1, col2, col3 = st.columns([3, 2, 1])

                        with col1:
                            st.write(f"**Username:** {pwd['username'] or 'Not specified'}")

                            # Password visibility logic
                            password_key = f"pwd_{pwd['id']}"

                            if password_key in st.session_state.visible_passwords:
                                st.success("🔓 Password Revealed:")
                                st.code(pwd['password'])
                                if st.button("🙈 Hide Password", key=f"hide_{pwd['id']}"):
                                    st.session_state.visible_passwords.discard(password_key)
                                    st.rerun()
                            else:
                                st.info("🔒 Password Hidden - Click to reveal")

                                # Create a unique form for each password
                                with st.form(key=f"reveal_form_{pwd['id']}"):
                                    verify_password = st.text_input(
                                        "Enter Master Password to reveal:",
                                        type="password",
                                        key=f"verify_input_{pwd['id']}"
                                    )
                                    verify_submit = st.form_submit_button("👁️ Show Password")

                                    if verify_submit:
                                        if verify_password:
                                            if vault.verify_master_password(verify_password):
                                                st.session_state.visible_passwords.add(password_key)
                                                st.success("✅ Password verified! Revealing...")
                                                st.rerun()
                                            else:
                                                st.error("❌ Incorrect master password!")
                                        else:
                                            st.error("Please enter your master password")

                            if pwd['notes']:
                                st.write(f"**Notes:** {pwd['notes']}")

                        with col2:
                            st.write(f"**Compression:** {pwd['compression_method'].upper()}")
                            st.write(f"**Ratio:** {pwd['compression_ratio']:.1f}%")
                            st.write(f"**Size:** {pwd['original_size']} → {pwd['compressed_size']} bytes")
                            st.write(f"**Created:** {pwd['created_at'][:10]}")

                        with col3:
                            # Delete functionality
                            with st.form(key=f"delete_form_{pwd['id']}"):
                                delete_password = st.text_input(
                                    "Master Password:",
                                    type="password",
                                    key=f"del_verify_{pwd['id']}",
                                    placeholder="Enter to delete"
                                )
                                delete_submit = st.form_submit_button("🗑️ Delete", type="secondary")

                                if delete_submit:
                                    if delete_password:
                                        if vault.verify_master_password(delete_password):
                                            vault.delete_password(pwd['id'])
                                            st.session_state.visible_passwords.discard(password_key)
                                            st.success("✅ Password deleted!")
                                            st.rerun()
                                        else:
                                            st.error("❌ Wrong password!")
                                    else:
                                        st.error("Enter master password")

        elif menu == "📊 Analytics":
            st.header("📊 Compression Analytics")

            passwords = vault.get_all_passwords()

            if not passwords:
                st.info("No data available. Add some passwords first!")
            else:
                col1, col2, col3 = st.columns(3)

                total_original = sum(p['original_size'] for p in passwords)
                total_compressed = sum(p['compressed_size'] for p in passwords)
                total_saved = total_original - total_compressed

                col1.metric("Total Original", f"{total_original:,} bytes")
                col2.metric("Total Compressed", f"{total_compressed:,} bytes")
                col3.metric("Total Saved", f"{total_saved:,} bytes")

                # Method analysis
                st.subheader("Compression Method Performance")
                method_stats = {}
                for pwd in passwords:
                    method = pwd['compression_method']
                    if method not in method_stats:
                        method_stats[method] = {'count': 0, 'total_ratio': 0, 'total_original': 0,
                                                'total_compressed': 0}
                    method_stats[method]['count'] += 1
                    method_stats[method]['total_ratio'] += pwd['compression_ratio']
                    method_stats[method]['total_original'] += pwd['original_size']
                    method_stats[method]['total_compressed'] += pwd['compressed_size']

                for method, stats in method_stats.items():
                    avg_ratio = stats['total_ratio'] / stats['count']
                    total_saved_method = stats['total_original'] - stats['total_compressed']
                    st.write(
                        f"**{method.upper()}**: {stats['count']} passwords, {avg_ratio:.1f}% avg compression, {total_saved_method} bytes saved")

                # Detailed table
                if st.checkbox("Show detailed password stats"):
                    df = pd.DataFrame(passwords)
                    st.dataframe(
                        df[['service_name', 'compression_method', 'original_size', 'compressed_size',
                            'compression_ratio']],
                        use_container_width=True
                    )

        elif menu == "🔧 Tools":
            st.header("🔧 Tools")

            tab1, tab2 = st.tabs(["Password Generator", "Strength Checker"])

            with tab1:
                st.subheader("🎲 Advanced Password Generator")

                col1, col2 = st.columns(2)
                with col1:
                    tool_length = st.slider("Length", 8, 64, 16, key="tool_length")
                    tool_symbols = st.checkbox("Symbols", value=True, key="tool_symbols")
                with col2:
                    tool_numbers = st.checkbox("Numbers", value=True, key="tool_numbers")
                    tool_uppercase = st.checkbox("Uppercase", value=True, key="tool_uppercase")

                if st.button("Generate Password", key="generate_tool"):
                    generated_pwd = generate_password(tool_length, tool_symbols, tool_numbers, tool_uppercase)
                    st.code(generated_pwd)
                    score, strength, emoji, feedback = check_password_strength(generated_pwd)
                    st.write(f"Strength: {emoji} {strength} ({score}/8)")

            with tab2:
                st.subheader("🔍 Password Strength Checker")

                test_password = st.text_input("Enter password to test:", type="password")

                if test_password:
                    score, strength, emoji, feedback = check_password_strength(test_password)

                    col1, col2 = st.columns(2)
                    with col1:
                        st.write(f"**Strength:** {emoji} {strength}")
                        st.write(f"**Score:** {score}/8")

                    with col2:
                        st.write(f"**Length:** {len(test_password)} characters")

                    if feedback:
                        st.write("**💡 Suggestions for improvement:**")
                        for suggestion in feedback:
                            st.write(f"• {suggestion}")
                    else:
                        st.success("✅ Excellent password!")

        elif menu == "🚪 Logout":
            st.subheader("🚪 Logout")
            st.write("Are you sure you want to logout?")
            col1, col2 = st.columns(2)
            with col1:
                if st.button("✅ Confirm Logout", type="primary"):
                    # Clear all session state
                    for key in ['logged_in', 'master_key', 'compression_stats', 'generated_password',
                                'visible_passwords']:
                        if key in st.session_state:
                            del st.session_state[key]
                    st.success("🚪 Logged out successfully!")
                    st.rerun()
            with col2:
                if st.button("❌ Cancel"):
                    st.info("Logout cancelled")


if __name__ == "__main__":
    main()