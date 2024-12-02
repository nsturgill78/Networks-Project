import requests
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from getpass import getpass

SERVER_URL = "https://127.0.0.1:5000"
SERVER_CERT = "server_cert.pem"  # Path to the server's self-signed certificate

# Load the server's public key
response = requests.get(f"{SERVER_URL}/public_key", verify=SERVER_CERT)
public_key = serialization.load_pem_public_key(response.content)

def encrypt_data(data):
    """Encrypts data using the server's public key."""
    return public_key.encrypt(
        data.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).hex()

def register():
    """Registers a voter."""
    name = input("Enter your name: ")
    password = getpass("Create a password (hidden): ")
    encrypted_name = encrypt_data(name)
    encrypted_password = encrypt_data(password)

    response = requests.post(f"{SERVER_URL}/register", json={
        "name": encrypted_name,
        "password": encrypted_password
    }, verify=SERVER_CERT)
    try:
        print(response.json())
    except Exception as e:
        print("Error decoding server response:", e)
        print("Raw server response:", response.text)

def vote():
    """Casts a vote."""
    voter_id = input("Enter your voter ID: ")
    password = getpass("Enter your password (hidden): ")

    encrypted_voter_id = encrypt_data(voter_id)
    encrypted_password = encrypt_data(password)

    # Step 1: Validate ID and password
    response = requests.post(f"{SERVER_URL}/vote", json={
        "voter_id": encrypted_voter_id,
        "password": encrypted_password
    }, verify=SERVER_CERT)

    try:
        result = response.json()
        if result["status"] == "error":
            print(result["message"])
            return

        # Step 2: Check if already voted
        if result["voted"]:
            print("You have already voted.")
            return

        # Step 3: Present voting options
        choice = input("Enter your vote (e.g., Candidate A, Candidate B): ")
        encrypted_choice = encrypt_data(choice)

        # Submit the vote
        response = requests.post(f"{SERVER_URL}/vote", json={
            "voter_id": encrypted_voter_id,
            "password": encrypted_password,
            "choice": encrypted_choice
        }, verify=SERVER_CERT)
        print(response.json())
    except Exception as e:
        print("Error decoding server response:", e)
        print("Raw server response:", response.text)

def check_status():
    """Checks voting status."""
    voter_id = input("Enter your voter ID: ")

    encrypted_voter_id = encrypt_data(voter_id)
    response = requests.get(f"{SERVER_URL}/status", params={
        "voter_id": encrypted_voter_id
    }, verify=SERVER_CERT)
    try:
        print(response.json())
    except Exception as e:
        print("Error decoding server response:", e)
        print("Raw server response:", response.text)

def main():
    """Main menu for the client."""
    while True:
        print("\nOptions:")
        print("1. Register")
        print("2. Vote")
        print("3. Check Voting Status")
        print("4. Exit")
        choice = input("Select an option: ")

        if choice == "1":
            register()
        elif choice == "2":
            vote()
        elif choice == "3":
            check_status()
        elif choice == "4":
            print("Exiting. Goodbye!")
            break
        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    main()
