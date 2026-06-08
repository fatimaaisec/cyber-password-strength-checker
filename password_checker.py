import re
import math


COMMON_PASSWORDS = [
    "password", "123456", "qwerty",
    "admin", "welcome", "password123"
]


def calculate_entropy(password):
    charset_size = 0

    if re.search(r"[a-z]", password):
        charset_size += 26

    if re.search(r"[A-Z]", password):
        charset_size += 26

    if re.search(r"\d", password):
        charset_size += 10

    if re.search(r"[!@#$%^&*()_+=\-{}\[\]:;\"'<>,.?/]", password):
        charset_size += 32

    if charset_size == 0:
        return 0

    entropy = len(password) * math.log2(charset_size)
    return round(entropy, 2)


def password_strength(password):
    score = 0
    feedback = []

    # Length
    if len(password) >= 12:
        score += 3
    elif len(password) >= 8:
        score += 2
    else:
        feedback.append("Use at least 8–12 characters.")

    # Uppercase
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Add uppercase letters.")

    # Lowercase
    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Add lowercase letters.")

    # Numbers
    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("Add numbers.")

    # Special chars
    if re.search(r"[!@#$%^&*()_+=\-]", password):
        score += 2
    else:
        feedback.append("Add special characters.")

    # Weak/common passwords
    if password.lower() in COMMON_PASSWORDS:
        score -= 5
        feedback.append("This password is extremely common.")

    # Repeated chars
    if re.search(r"(.)\1{2,}", password):
        score -= 2
        feedback.append("Avoid repeated characters.")

    # Sequential patterns
    if "123" in password or "abc" in password.lower():
        score -= 2
        feedback.append("Avoid predictable sequences.")

    entropy = calculate_entropy(password)

    if score <= 2:
        level = "Weak"
    elif score <= 5:
        level = "Medium"
    elif score <= 8:
        level = "Strong"
    else:
        level = "Very Strong"

    return level, entropy, feedback


password = input("Enter password: ")

strength, entropy, feedback = password_strength(password)

print("\n====== Password Analysis ======")
print("Strength:", strength)
print("Entropy:", entropy, "bits")

if feedback:
    print("\nSuggestions:")
    for tip in feedback:
        print("-", tip)
else:
    print("\nExcellent password!")
