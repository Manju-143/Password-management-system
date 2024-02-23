import string
import random
import os

# Function to apply Caesar Cipher encryption
def caesar_cipher(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            shifted_index = (string.ascii_letters.index(char) + shift) % 26
            encrypted_char = string.ascii_letters[shifted_index]
            encrypted_text += encrypted_char
        else:
            encrypted_text += char
    return encrypted_text

# Function to check password strength and suggest improvements
def check_password_strength(password):
    overall_strength = 'Weak'
    suggestions = []

    if len(password) >= 8 and any(char.isupper() for char in password) \
            and any(char.islower() for char in password) \
            and any(char in string.punctuation for char in password):
        overall_strength = 'Strong'
    elif len(password) >= 5 and len(password) < 8:
        overall_strength = 'Medium'

    if len(password) < 5:
        suggestions.append("Increase the length of the password to at least 5 characters.")
    elif len(password) >= 5 and len(password) < 8:
        if not any(char.isupper() for char in password):
            suggestions.append("Include at least one uppercase letter.")
        if not any(char.islower() for char in password):
            suggestions.append("Include at least one lowercase letter.")
        if not any(char in string.punctuation for char in password):
            suggestions.append("Include at least one symbol (e.g., !, @, #, etc.).")
    elif len(password) >= 8:
        if not any(char.isupper() for char in password):
            suggestions.append("Include at least one uppercase letter.")
        if not any(char.islower() for char in password):
            suggestions.append("Include at least one lowercase letter.")
        if not any(char in string.punctuation for char in password):
            suggestions.append("Include at least one symbol (e.g., !, @, #, etc.).")
            
    return overall_strength, suggestions

# Function to generate password
def generate_password():
    length = random.randint(8, 13)
    password = ''.join(random.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(length))
    return password

# Function to store password
def store_password(password):
    encrypted_password = caesar_cipher(password, 3)  # Encrypt with Caesar Cipher shift of 3
    print("Original Password:", password)
    print("Encrypted Password:", encrypted_password)

    with open('passwords.txt', 'a') as file:
        file.write(f'{encrypted_password}\n')

    return os.path.abspath('passwords.txt')

# Function to get stored password
def get_stored_password():
    try:
        with open('passwords.txt', 'r') as file:
            lines = file.readlines()

        if lines:
            encrypted_password = lines[-1].strip()
            decrypted_password = caesar_cipher(encrypted_password, -3)  # Decrypt with Caesar Cipher shift of -3
            return decrypted_password
        else:
            return None
    except FileNotFoundError:
        return None

# Function to print decrypted passwords from the file
def print_decrypted_passwords():
    try:
        with open('passwords.txt', 'r') as file:
            lines = file.readlines()

        if lines:
            print("Decrypted Passwords:")
            for line in lines:
                encrypted_password = line.strip()
                decrypted_password = caesar_cipher(encrypted_password, -3)  # Decrypt with Caesar Cipher shift of -3
                print("Decrypted Password:", decrypted_password)
        else:
            print("No passwords stored in the file.")
    except FileNotFoundError:
        print("File 'passwords.txt' not found.")

print("Welcome to the password manager. What would you like to do?")
choice = ''

while choice != 'q':
    print("\n[1] Enter 1 to check password strength.")
    print("[2] Enter 2 to generate a password.")
    print("[3] Enter 3 to store a password.")
    print("[4] Enter 4 to get a stored password.")
    print("[5] Enter 5 to print decrypted passwords from the file.")
    print("[q] Enter q to quit.")

    choice = input("\nWhat would you like to do? ")

    if choice == '1':
        password = input("Enter password: ")
        overall_strength, suggestions = check_password_strength(password)
        print("Overall Password Strength:", overall_strength)
        if suggestions:
            print("Suggestions for improvement:")
            for suggestion in suggestions:
                print(suggestion)
    elif choice == '2':
        password = generate_password()
        print("Generated password:", password)
    elif choice == '3':
        password = input("Enter password to store: ")
        file_path = store_password(password)
        print("Password stored successfully. File saved at:", file_path)
    elif choice == '4':
        stored_password = get_stored_password()
        if stored_password:
            print("Stored password:", stored_password)
        else:
            print("No stored password found.")
    elif choice == '5':
        print_decrypted_passwords()
    elif choice == 'q':
        print("\nThanks for using the password manager. Goodbye!")
    else:
        print("\nInvalid input. Please try again.")
