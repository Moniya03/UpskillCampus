import string
import secrets
import re

# This file contains helper utilities like the password generator and strength checker.

def generate_password(length=16, include_symbols=True, include_numbers=True):
    """
    Generates a cryptographically secure random password.
    """
    alphabet = string.ascii_letters
    if include_numbers:
        alphabet += string.digits
    if include_symbols:
        alphabet += string.punctuation
    
    password = ''.join(secrets.choice(alphabet) for i in range(length))
    return password

def check_password_strength(password: str):
    """
    Analyzes password strength and returns a score and feedback.
    """
    score = 0
    feedback = []
    
    if not password:
        return 0, ["Password cannot be empty."]

    # Length check
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    
    # Character type checks
    if re.search(r"[a-z]", password):
        score += 1
    if re.search(r"[A-Z]", password):
        score += 1
    if re.search(r"\d", password):
        score += 1
    if re.search(r"[\W_]", password): # Symbols
        score += 1
        
    # Provide feedback based on score
    if score <= 2:
        strength = "Very Weak"
        feedback.append("Consider a longer password with more character types.")
    elif score <= 4:
        strength = "Medium"
        feedback.append("Good, but could be stronger with more symbols or length.")
    else:
        strength = "Strong"
        feedback.append("This is a strong password!")
        
    return strength, score, feedback
