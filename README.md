# 🔐 Secure Password Vault — Compression + Encryption

## 📌 Overview
This project is a **secure password manager** that combines **lossless data compression** and **AES-based encryption** to optimize storage space and enhance security. It allows users to store credentials, compress them using multiple algorithms (LZMA, Huffman, ZLIB), encrypt them, and view analytics like compression ratios and entropy.

Built using **Python** and **Streamlit**.

---

## ✨ Features
- **Multi-Algorithm Compression**: Choose between LZMA, ZLIB, and Huffman coding.
- **AES Encryption (Fernet)**: Secure passwords using strong encryption.
- **Entropy & Compression Analytics**: View original size, compressed size, and % savings.
- **Interactive Dashboard**: Built with Streamlit for easy use.
- **Password Generator & Strength Checker**.

---

---

## ⚙️ Installation


Clone the repository
```bash
git clone https://github.com/your-username/Secure-Password-Vault-Compression-Encryption.git
cd Secure-Password-Vault-Compression-Encryption

2. Run the Application
streamlit run main.py


🖥️ Usage
	•	Add a new password with optional notes.
	•	Select a compression method before encryption.
	•	View analytics for storage savings.
	•	Generate and check password strength.

Example_Output
Total Original: 667 bytes
Total Compressed: 543 bytes
Space Saved: 124 bytes

🧠 How It Works
	1.	User enters password + notes.
	2.	Data is compressed using the chosen lossless algorithm.
	3.	Compressed data is encrypted using Fernet (AES).
	4.	Encrypted data is stored in SQLite.
	5.	Analytics tab displays storage savings & performance.


🤝 Contributing
Pull requests are welcome. Please open an issue to discuss any major changes.

👨‍💻 Author
J. Nithin Joel, Raghul, Raashmika, Vishnu, N  L Dev Aadhitya 
---
If you want, I can also **design a simple GitHub repository cover banner** (with a lock + compression icon + “Secure Password Vault”) so the repo looks professional.  
Do you want me to make that banner for you?
