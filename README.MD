🔐 Password Manager
A secure, local password manager with a user-friendly web interface built using Python and Streamlit. All data is encrypted locally and never leaves your machine.

✨ Core Features
Secure Encryption: Uses a master password to encrypt the entire vault with PBKDF2 and Fernet encryption.

Full Password Management: Add, update, delete, and search for all your passwords.

Password Generator: Create strong, random passwords on the fly.

Local-First Storage: Your encrypted vault is stored safely on your computer in a password_manager.db file.

🚀 Quick Start
Prerequisites
Python 3.8+

Installation & Run
Follow these steps in your terminal to get the application running.

# 1. Clone the repository
git clone <your-repository-url>
cd <repository-folder>

# 2. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install the required packages
pip install streamlit cryptography

# 4. Run the application
streamlit run app.py

The application will open in a new browser tab.

🛡️ Security
Your master password is never stored. It is used to generate an in-memory encryption key that securely locks and unlocks your password vault. Without it, your data is unreadable.