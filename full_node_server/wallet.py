import os
import base64
import hashlib
import jwt
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives import padding as sym_padding


class Wallet:
    def __init__(self, private_key_hex=None):
        if private_key_hex:
            self.private_key = bytes.fromhex(private_key_hex)
        else:
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
        self.public_key = self.private_key.public_key()
        self.address = self.generate_address()

    def generate_address(self):
        # Generate an address based on the public key
        pub_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        sha256_pk = hashlib.sha256(pub_bytes).digest()
        ripemd160_pk = hashlib.new("ripemd160", sha256_pk).digest()
        versioned_payload = b"\x00" + ripemd160_pk
        sha256_vp = hashlib.sha256(versioned_payload).digest()
        checksum = hashlib.sha256(sha256_vp).digest()[:4]
        binary_address = versioned_payload + checksum
        return self.base58_encode(binary_address)

    def base58_encode(self, data):
        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        num = int.from_bytes(data, "big")
        encoded = ""
        while num > 0:
            num, rem = divmod(num, len(alphabet))
            encoded = alphabet[rem] + encoded
        n_pad = len(data) - len(data.lstrip(b"\x00"))
        return "1" * n_pad + encoded

    def sign_message(self, message):
        signature = self.private_key.sign(
            message.encode(),
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode("utf-8")

    def verify_message(self, public_key, message, signature):
        try:
            public_key.verify(
                base64.b64decode(signature),
                message.encode(),
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False


class Patient(Wallet):
    def __init__(self, first_name, last_name, email):
        super().__init__()
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.patient_address = self.generate_patient_address()

    def generate_patient_address(self):
        # Generate a deterministic patient address using double sha256
        address_input = (self.first_name + self.last_name + self.email).encode('utf-8')
        return hashlib.sha256(hashlib.sha256(address_input).digest()).hexdigest()

    def encrypt_data(self, data):
        # Generate a random 256-bit key and IV for AES encryption
        key = os.urandom(32)
        iv = os.urandom(16)
        
        # Pad the data to make it a multiple of the block size
        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(data.encode()) + padder.finalize()
        
        # Encrypt the data using AES-CBC
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Return the encrypted data along with the key and IV
        return encrypted_data, key, iv

    def pointer(self, record_id, vo_public_key):
        # Encrypt the record ID with the VO's public key using RSA
        record_id_bytes = record_id.to_bytes(4, byteorder='big')
        encrypted_with_vo = vo_public_key.encrypt(
            record_id_bytes,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Return the fully encrypted pointer
        return base64.b64encode(encrypted_with_vo).decode('utf-8')

    def app_sig(self, data_pointer, requester_public_key):
        # Encrypt the data pointer using AES
        encrypted_data, key, iv = self.encrypt_data(data_pointer)

        # Encrypt the AES key with the requester's public key using RSA
        encrypted_key = requester_public_key.encrypt(
            key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Combine encrypted data, encrypted key, and IV
        combined_data = base64.b64encode(iv + encrypted_key + encrypted_data)

        # Return the encrypted approval signature
        return combined_data.decode('utf-8')


class Requester(Wallet):
    def __init__(self):
        super().__init__()
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.rsa_public_key = self.rsa_private_key.public_key()
        print(f'Requester Address: {self.address}')

    def decrypt_data(self, encrypted_message):
        # Decode the base64 encoded data
        encrypted_message = base64.b64decode(encrypted_message)

        # Extract the IV, encrypted AES key, and encrypted data
        iv = encrypted_message[:16]
        encrypted_key = encrypted_message[16:272]
        encrypted_data = encrypted_message[272:]

        # Decrypt the AES key using the requester's private RSA key
        key = self.rsa_private_key.decrypt(
            encrypted_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Decrypt the data using AES-CBC
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Remove padding
        unpadder = sym_padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()

        # Return the decrypted data
        return data.decode('utf-8')

    def requestor_generate(self, approval_signature):
        # Decrypt the approval signature
        decrypted_data = self.decrypt_data(approval_signature)

        # This VO_submission is what the requester will send to the VO
        return decrypted_data

    def create_jwt_for_api(self, claims):
        """
        Create a JWT for API authentication.
        claims: A dictionary of claims to include in the JWT.
        """
        token = jwt.encode(claims, self.rsa_private_key, algorithm="RS256")
        return token


class VerifiedAuthority(Wallet):
    def __init__(self):
        super().__init__()
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.rsa_public_key = self.rsa_private_key.public_key()
        print(f'Verified Authority Address: {self.address}')

    def vo_verify(self, vo_submission):
        # Fully decrypt the VO_submission with the VO's private key
        decrypted_by_vo = self.rsa_private_key.decrypt(
            base64.b64decode(vo_submission),
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Assuming the result is the original record ID
        record_id = int.from_bytes(decrypted_by_vo, byteorder='big')
        
        # Return the record ID for validation
        return record_id

    def verify_jwt(self, token, requester_public_key):
        """
        Verify the JWT token provided by the requester.
        token: The JWT token string.
        requester_public_key: The public key of the requester.
        """
        try:
            decoded = jwt.decode(token, requester_public_key, algorithms=["RS256"])
            return decoded  # Returns the claims if valid
        except jwt.ExpiredSignatureError:
            print("Signature has expired.")
            return None
        except jwt.InvalidTokenError:
            print("Invalid token.")
            return None


if __name__ == "__main__":

    patient = Patient("John", "Doe", "john.doe@example.com")
    requester = Requester()
    vo = VerifiedAuthority()

    # Patient creates a pointer to a medical record (e.g., record ID = 1234)
    record_id = 1234
    data_pointer = patient.pointer(record_id, vo.rsa_public_key)
    print("Data Pointer:", data_pointer)

    # Patient generates an approval signature (App_Sig) for the requester
    app_sig = patient.app_sig(data_pointer, requester.rsa_public_key)
    print("Approval Signature (App_Sig):", app_sig)

    # Requester generates a VO submission using the approval signature
    vo_submission = requester.requestor_generate(app_sig)
    print("VO Submission:", vo_submission)

    # VO verifies the VO submission and retrieves the original record ID
    retrieved_record_id = vo.vo_verify(vo_submission)
    print("Retrieved Record ID:", retrieved_record_id)

    # Requester creates a JWT for the API call
    claims = {
        "requester_address": requester.address,
        "record_id": retrieved_record_id,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5)
    }
    jwt_token = requester.create_jwt_for_api(claims)
    print("JWT for API Call:", jwt_token)

    # VO verifies the JWT during the API call
    verified_claims = vo.verify_jwt(jwt_token, requester.rsa_public_key)
    if verified_claims:
        print("Verified Claims:", verified_claims)
    else:
        print("JWT Verification Failed")
