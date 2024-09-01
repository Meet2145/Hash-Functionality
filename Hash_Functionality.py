import hashlib

def hash_message(message, algorithm='sha256'):
    """
    Generate a hash for a given message using the specified algorithm.

    :param message: The input message to be hashed.
    :param algorithm: The hash algorithm to use ('md5', 'sha1', 'sha256').
    :return: The hexadecimal hash string.
    """
    message_bytes = message.encode('utf-8')

    if algorithm.lower() == 'md5':
        hash_object = hashlib.md5(message_bytes)
    elif algorithm.lower() == 'sha1':
        hash_object = hashlib.sha1(message_bytes)
    elif algorithm.lower() == 'sha256':
        hash_object = hashlib.sha256(message_bytes)
    else:
        raise ValueError("Unsupported hash algorithm. Choose 'md5', 'sha1', or 'sha256'.")

    return hash_object.hexdigest()

def main():
    message = input("Enter the message to hash: ")

    print("Choose a hash algorithm (md5, sha1, sha256): ")
    algorithm = input().lower()

    hash_value = hash_message(message, algorithm)
    print(f"The {algorithm.upper()} hash of the message is: {hash_value}")

if __name__ == "__main__":
    main()