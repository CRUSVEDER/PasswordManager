import bcrypt
import os
import base64
import json
import random
import string
import pyfiglet
import time
import pyotp
import qrcode 
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from rich import print


# ASCII Art Header
result = pyfiglet.figlet_format("CRUSVAULT", font="slant")
print(f"[bold cyan]{result}[/bold cyan]")

console = Console()


#2FA System

key = "myfirstcrusvault"
  
uri = pyotp.totp.TOTP(key).provisioning_uri( 
    name='crusveder', 
    issuer_name='crus') 
  
print(uri) 
  
# # Qr code generation step {use for only first time and comment out after generating qr code or else it will generate new qr each time}

# qrcode.make(uri).save("qr.png") 
# """Verifying stage starts"""


totp = pyotp.TOTP(key) 
  
# verifying the code 
while True: 
    code = input("Enter the Code: ")
    if totp.verify(code):
        print("[green]2FA Verified Successfully![/green]")
        break
    else:
        print("[red]Invalid Code. Try Again.[/red]")

# Encryption Functions
def generate_key(master_password):
    salt = b"password_vault_salt"
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    key = kdf.derive(master_password.encode())
    return base64.urlsafe_b64encode(key)

def encrypt_data(key, data):
    fernet = Fernet(key)
    return fernet.encrypt(data.encode())

def decrypt_data(key, encrypted_data):
    try:
        fernet = Fernet(key)
        return fernet.decrypt(encrypted_data).decode()
    except Exception as e:
        console.print(f"[red]Error decrypting data: {e}[/red]")
        raise ValueError("Decryption failed. Please check the master password and vault integrity.")

def save_to_file(file_name, encrypted_data):
    with open(file_name, 'wb') as file:
        file.write(encrypted_data)

def load_from_file(file_name):
    if not os.path.exists(file_name):
        return None
    with open(file_name, 'rb') as file:
        return file.read()

# Vault Management
def rename_vault(old_name, new_name):
    if os.path.exists(old_name):
        os.rename(old_name, new_name)
        console.print(f"[green]Vault renamed to '{new_name}' successfully![/green]")
    else:
        console.print("[red]Vault not found.[/red]")

def delete_vault(vault_file):
    if os.path.exists(vault_file):
        os.remove(vault_file)
        console.print(f"[red]Vault '{vault_file}' deleted successfully![/red]")
    else:
        console.print("[red]Vault not found.[/red]")

def create_new_vault(vault_file):
    if os.path.exists(vault_file):
        console.print("[red]Vault already exists.[/red]")
    else:
        save_to_file(vault_file, encrypt_data(generate_key("default"), "{}"))
        console.print(f"[green]Vault '{vault_file}' created successfully![/green]")

# Vault Functions
def add_password(vault_file, master_password, service, password):
    key = generate_key(master_password)
    vault_data = load_from_file(vault_file)
    
    try:
        if vault_data:
            vault = decrypt_data(key, vault_data)
        else:
            vault = "{}"
    except Exception:
        console.print("[bold red]Error decrypting vault data.[/bold red]")
        return

    vault_dict = json.loads(vault) if vault else {}
    encrypted_password = encrypt_data(key, password)
    vault_dict[service] = encrypted_password.decode()

    encrypted_vault = encrypt_data(key, json.dumps(vault_dict))
    save_to_file(vault_file, encrypted_vault)
    console.print("[green]Password added successfully![/green]")

def retrieve_password(vault_file, master_password, service):
    key = generate_key(master_password)
    vault_data = load_from_file(vault_file)
    
    if not vault_data:
        console.print("[bold red]No passwords stored yet.[/bold red]")
        return None

    try:
        vault = decrypt_data(key, vault_data)
        vault_dict = json.loads(vault)
        encrypted_password = vault_dict.get(service)
        if not encrypted_password:
            return "[yellow]Service not found in vault.[/yellow]"
        return decrypt_data(key, encrypted_password)
    except Exception:
        console.print("[bold red]Error retrieving password.[/bold red]")
        return None

def view_services(vault_file, master_password):
    key = generate_key(master_password)
    vault_data = load_from_file(vault_file)
    
    if not vault_data:
        console.print("[bold red]No passwords stored yet.[/bold red]")
        return []

    try:
        vault = decrypt_data(key, vault_data)
        vault_dict = json.loads(vault)
        return list(vault_dict.keys())
    except Exception:
        console.print("[bold red]Error retrieving services.[/bold red]")
        return []

def edit_password(vault_file, master_password, service, new_password):
    key = generate_key(master_password)
    vault_data = load_from_file(vault_file)
    
    if not vault_data:
        console.print("[bold red]No passwords stored yet.[/bold red]")
        return

    try:
        vault = decrypt_data(key, vault_data)
        vault_dict = json.loads(vault)
        
        if service in vault_dict:
            encrypted_password = encrypt_data(key, new_password)
            vault_dict[service] = encrypted_password.decode()
            encrypted_vault = encrypt_data(key, json.dumps(vault_dict))
            save_to_file(vault_file, encrypted_vault)
            console.print("[green]Password updated successfully![/green]")
        else:
            console.print("[yellow]Service not found in vault.[/yellow]")
    except Exception:
        console.print("[bold red]Error editing password.[/bold red]")

def delete_password(vault_file, master_password, service):
    key = generate_key(master_password)
    vault_data = load_from_file(vault_file)
    
    if not vault_data:
        console.print("[bold red]No passwords stored yet.[/bold red]")
        return

    try:
        vault = decrypt_data(key, vault_data)
        vault_dict = json.loads(vault)
        
        if service in vault_dict:
            del vault_dict[service]
            encrypted_vault = encrypt_data(key, json.dumps(vault_dict))
            save_to_file(vault_file, encrypted_vault)
            console.print("[red]Password deleted successfully![/red]")
        else:
            console.print("[yellow]Service not found in vault.[/yellow]")
    except Exception:
        console.print("[bold red]Error deleting password.[/bold red]")

# Password Generator and Checker
def generate_password(length=12):
    if length < 6:
        console.print("[red]Password length should be at least 6 characters.[/red]")
        return None

    characters = string.ascii_letters + string.digits + string.punctuation
    password = [
        random.choice(string.ascii_uppercase),
        random.choice(string.ascii_lowercase),
        random.choice(string.digits),
        random.choice(string.punctuation)
    ]
    password += [random.choice(characters) for _ in range(length - 4)]
    random.shuffle(password)
    return ''.join(password)

def check_password_strength(password):
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_digit = any(char.isdigit() for char in password)
    has_special = any(char in string.punctuation for char in password)
    strength = sum([has_upper, has_lower, has_digit, has_special])

    if strength == 4:
        return "Strong"
    elif strength == 3:
        return "Moderate"
    else:
        return "Weak"

# Main Functionality
if __name__ == "__main__":
    vault_file = "password_vault.lock"
    master_password = Prompt.ask("[bold cyan]Enter your master password[/bold cyan]", password=True)

    while True:
        console.print("\n[bold cyan]Main Menu[/bold cyan]")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Option", style="dim", width=5)
        table.add_column("Action", justify="left")
        table.add_row("1", "Add Password")
        table.add_row("2", "Retrieve Password")
        table.add_row("3", "View All Services")
        table.add_row("4", "Edit Password")
        table.add_row("5", "Delete Password")
        table.add_row("6", "Rename Vault")
        table.add_row("7", "Delete Vault")
        table.add_row("8", "Create New Vault")
        table.add_row("9", "Switch Vault")
        table.add_row("10", "Show Vault Location")
        table.add_row("11", "Generate Password")
        table.add_row("12", "Check Password Strength")
        table.add_row("13", "Exit")
        console.print(table)

        choice = Prompt.ask("[bold green]Choose an option[/bold green]")

        if choice == "1":
            service = Prompt.ask("[bold yellow]Enter the service name[/bold yellow]")
            password = Prompt.ask("[bold yellow]Enter the password[/bold yellow]", password=True)
            add_password(vault_file, master_password, service, password)

        elif choice == "2":
            service = Prompt.ask("[bold yellow]Enter the service name[/bold yellow]")
            password = retrieve_password(vault_file, master_password, service)
            console.print(f"[bold green]Stored password for {service}:[/bold green] {password}")

        elif choice == "3":
            services = view_services(vault_file, master_password)
            if services:
                console.print("[bold cyan]Services stored in the vault:[/bold cyan]")
                for service in services:
                    console.print(f"- {service}")
            else:
                console.print("[bold red]No services found in the vault.[/bold red]")

        elif choice == "4":
            service = Prompt.ask("[bold yellow]Enter the service name[/bold yellow]")
            new_password = Prompt.ask("[bold yellow]Enter the new password[/bold yellow]", password=True)
            edit_password(vault_file, master_password, service, new_password)

        elif choice == "5":
            service = Prompt.ask("[bold yellow]Enter the service name[/bold yellow]")
            delete_password(vault_file, master_password, service)

        elif choice == "6":
            new_name = Prompt.ask("[bold yellow]Enter the new vault name[/bold yellow]")
            rename_vault(vault_file, new_name)
            vault_file = new_name

        elif choice == "7":
            delete_vault(vault_file)

        elif choice == "8":
            new_name = Prompt.ask("[bold yellow]Enter the new vault name[/bold yellow]")
            create_new_vault(new_name)

        elif choice == "9":
            new_name = Prompt.ask("[bold yellow]Enter the vault name to switch to[/bold yellow]")
            if os.path.exists(new_name):
                vault_file = new_name
                console.print(f"[green]Switched to vault '{vault_file}'.[/green]")
            else:
                console.print("[red]Vault not found.[/red]")

        elif choice == "10":
            console.print(f"[cyan]Vault location: {os.path.abspath(vault_file)}[/cyan]")

        elif choice == "11":
            length = Prompt.ask("[bold yellow]Enter the desired password length[/bold yellow]", default="12")
            try:
                length = int(length)
                password = generate_password(length)
                if password:
                    console.print(f"[bold green]Generated password:[/bold green] {password}")
            except ValueError:
                console.print("[red]Invalid input. Please enter a valid number.[/red]")

        elif choice == "12":
            password = Prompt.ask("[bold yellow]Enter the password to check[/bold yellow]")
            strength = check_password_strength(password)
            console.print(f"[bold cyan]Password strength:[/bold cyan] {strength}")

        elif choice == "13":
            console.print("[bold cyan]Goodbye![/bold cyan]")
            break

        else:
            console.print("[bold red]Invalid choice. Please try again.[/bold red]")
