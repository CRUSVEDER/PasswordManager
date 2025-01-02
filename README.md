

# Password Vault Manager

This is a simple Python-based password vault manager that allows you to securely store, retrieve, and manage your passwords using encryption and hashing techniques. It also includes features for password generation and strength checking.

## Features

- **Add Password**: Securely store passwords for various services.
- **Retrieve Password**: Retrieve the hashed password for a specific service.
- **View All Services**: List all stored services in the vault.
- **Rename Vault**: Rename the vault file.
- **Delete Vault**: Delete the entire vault.
- **Create New Vault**: Create a new, separate vault file for password storage.
- **Switch Vault**: Switch between different vault files.
- **Show Vault Location**: Display the location of the current vault file.
- **Password Generator**: Generate strong random passwords.
- **Password Strength Checker**: Check the strength of a given password.

## Requirements

- Python 3.6+
- The following Python libraries:
  - `cryptography` for encryption and decryption
  - `bcrypt` for hashing passwords
  - `rich` for enhanced terminal output
  - `pyfiglet` for ASCII art

You can install the required libraries by running:

```bash
pip install cryptography bcrypt rich pyfiglet
```

## Setup

1. Clone or download the repository.
2. Install the required dependencies using `pip`.
3. Run the script:

```bash
python password_vault.py
```

## How It Works

### Vault Management:
- The program creates a **vault** to store passwords, which is encrypted using a key derived from your master password.
- Passwords are **hashed** using `bcrypt` before being stored, ensuring that the vault only contains hashed values.
- The vault file is securely encrypted with **Fernet** encryption.

### Encryption Key:
- The encryption key is derived from your master password using the **PBKDF2HMAC** key derivation function.
- The key is used to encrypt and decrypt the vault file, ensuring that your passwords are securely stored.

### Features Walkthrough:

- **Add Password**: Add a password for a service to the vault, where it's hashed and stored.
- **Retrieve Password**: Retrieve the hashed password for a specific service.
- **View All Services**: Show a list of all services currently stored in the vault.
- **Rename Vault**: Rename the current vault file.
- **Delete Vault**: Completely remove the vault and all stored data.
- **Create New Vault**: Create a new vault file for a fresh start.
- **Switch Vault**: Switch between different vault files to manage multiple vaults.
- **Show Vault Location**: Display the file path of the current vault.

### Password Generation:
- The program can generate a random password of a specified length, ensuring it contains a mix of upper and lowercase letters, digits, and special characters.

### Password Strength Checking:
- Check the strength of a password. It will be categorized as **Strong**, **Moderate**, or **Weak** based on the presence of uppercase letters, lowercase letters, digits, and special characters.

## Example Usage

```plaintext
Welcome to the Password Vault
1. Add Password
2. Retrieve Password Hash
3. View All Services
4. Rename Vault
5. Delete Vault
6. Create New Vault
7. Switch Vault
8. Show Vault Location
9. Exit

Choose an option:
```

### Password Generator:

```plaintext
1. Generate a new password
2. Check password strength
3. Exit
```

### Example Commands:

- **Add a password**: `1`
- **Retrieve a password**: `2`
- **Generate a new password**: `1`
- **Check password strength**: `2`

## Security Considerations

- **Do not hard-code passwords**: The program ensures that passwords are securely hashed and encrypted, but always be careful with storing secrets in code.
- **Use strong master passwords**: The master password is used to derive the encryption key for the vault, so it's essential that you use a strong, unique master password.
- **Environment variables**: For additional security, consider storing your master password or encryption keys in environment variables or a secure key management service rather than hard-coding them in your script.

## Contributions

Feel free to open issues or pull requests to improve the program or add additional features.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.



