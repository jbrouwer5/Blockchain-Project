from hashlib import sha256
from datetime import datetime, timedelta
from binascii import unhexlify, hexlify

import csv
import os
import hashlib
import ecdsa
import json
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


"""creating the class object to hold the Blocks"""


class Block:
    def __init__(self, Transactions):
        self.MagicNumber = "0xD984BEF9"  # default
        self.Blocksize = 0  # default
        self.Transactions_input = Transactions  # this is a list of the Transactions that are input at creation
        self.Transactions = self.get_transactions() # i want to store the transactions by their hashes
        self.TransactionCounter = len(self.Transactions)  # set to be the number of transactions in the block
        self.BlockHeader = Header(self.Transactions)  # this is the Header object that is initiatied when the Block is created
        #self.Blockhash = self.block_hash()  # the double sha hash of this block
        self.Blockhash = None  # the block hash, set after mining
        self.mine_block(difficulty=4)  # default difficulty for PoW

    def get_transactions(self):
        transaction_hashes = []
        for t in range(len(self.Transactions_input)):
            transaction_hashes.append(self.Transactions_input[t].TransactionHash)
        return transaction_hashes
    
    """creating the double sha hash representing this block, incorporating data from the Block's Header"""

    def block_hash(self):
        string_to_hash = (
            str(self.BlockHeader.Timestamp)
            + str(self.BlockHeader.hashMerkleRoot)
            + str(self.BlockHeader.Bits)
            + str(self.BlockHeader.Nonce)
            + str(self.BlockHeader.hashPrevBlock)
        )
        return sha256(sha256(string_to_hash.encode('utf-8')).digest()).hexdigest()

        """string_to_hash += str(self.BlockHeader.Nonce)
        string_to_hash += str(self.BlockHeader.hashPrevBlock)
        bytes_to_hash = bytes(string_to_hash, "utf-8")
        return sha256(sha256(bytes_to_hash).hexdigest().encode("utf-8")).hexdigest()"""
    
    def mine_block(self, difficulty):
        target = '0' * difficulty
        self.BlockHeader.Nonce = 0
        self.Blockhash = self.block_hash()

        while self.Blockhash[:difficulty] != target:
            self.BlockHeader.Nonce += 1
            self.Blockhash = self.block_hash()

        print(f"Block mined with hash: {self.Blockhash} after {self.BlockHeader.Nonce} attempts")

    def printBlock(self):
        print(f"Magic Number is f{self.MagicNumber}")
        print(f"Block Size is {self.Blocksize}")
        print(f"Block Header is {self.BlockHeader}")
        print(f"Transaction Counter is {self.TransactionCounter}")
        l = len(self.Transactions)
        print(f"There are {l} transactions and the List of Transactions is:")
        for i in range(l):
            print(self.Transactions[i])
        print(f"The Block Hash is {self.Blockhash}")


"""creating the Header object for each block.  this takes the list of transaction hashes for the Block as input.
I build a Merkle Tree which i store as a list of hash lists at each level in the tree as well as create the Merkle Root itself"""


class Header:
    def __init__(self, Block_Transactions):
        self.Block_Transactions = Block_Transactions
        self.Version = 1
        self.hashPrevBlock = "Unattached to Blockchain"  # initiated as an unattached block, will change if it joins the Blockchain
        self.MerkleTree = (
            self.make_merkle_tree()
        )  # Merkle Tree of the transactions in the Block
        # because i am not building a Merkle Tree if there is only 1 transaction I have different forms of output
        # hence the if statement to parse that (rather than make the 1 transaction case more complicated)
        if len(self.MerkleTree) == 1:
            self.hashMerkleRoot = self.MerkleTree[-1][0]
        else:
            self.hashMerkleRoot = self.MerkleTree[-1][0].decode(
                "utf-8"
            )  # Merkle Root of the transactions in the Block
        self.Timestamp = int(
            round(datetime.now().timestamp())
        )  # time the block is created (as an integer)
        self.Bits = 0  # default
        self.Nonce = 0  # default

    """re-using my Merkle Root code from Lab 4, so i kept the hexilify/unhexilify for the big/little endian
    management in this code to generate the merkle root"""

    def make_merkle_tree(self):
        # i have to create an empty list and iterate the hashes into it, as if i just take the hashes directly
        # the calculations below impact my original transacion list
        tx_list = []
        merkle_tree_hashes = []
        for tx in range(len(self.Block_Transactions)):
            tx_list.append(self.Block_Transactions[tx])
        # end of that set up process
        if len(tx_list) == 0:
            return [["nothing to hash"]]
        elif len(tx_list) == 1:
            return [tx_list]
        counter = 1
        while len(tx_list) > 1:
            if len(tx_list) % 2 != 0:
                tx_list.append(tx_list[-1])
            merkle_tree_hashes.append(tx_list)
            new_tx_list = []
            for i in range(int(len(tx_list) / 2)):
                left = tx_list[i * 2]
                right = tx_list[i * 2 + 1]
                sha_left_to_bytes = unhexlify(left)[::-1]
                sha_right_to_bytes = unhexlify(right)[::-1]
                root_temp = hexlify(
                    sha256(
                        sha256(sha_left_to_bytes + sha_right_to_bytes).digest()
                    ).digest()[::-1]
                )
                new_tx_list.append(root_temp)
            counter += 1
            tx_list = new_tx_list
        merkle_tree_hashes.append([root_temp])
        return merkle_tree_hashes
        # return root_temp.decode("utf-8")


"""creating the Transaction object"""
"""amended to now include the following fields:
Version Number: integer
Patient Address: Hash address
Verified Organisaiton Address: Hash address
Hippa Field ID: Integer representing the correct category
Summary Available: Boolean
Data: Encrypted pointer to Data in VO Database
Requestor Address: Null (Null for new transaction, input if there is arequest to share data)
Approval signature: Signature hash
Transaction hash: Hash"""


class Transaction:
    def __init__(self, Patient_Ad, VO_Ad, H_ID, Summ_Av, Pointer):
        self.VersionNumber = 1 #default
        self.PatientAddress = Patient_Ad #input from database at creation
        self.VOAddress = VO_Ad #input from databse at creation
        self.HippaID = H_ID #input from database at creation
        self.SummaryAvail = True #default
        self.Data = Pointer #need to call pointer(database_ID, PatientAddress, VOAddress) from Wallet
        self.RequestorAddress = 'Null' #default at creation.  This is updated to RequestorAddress when generating an aaproval_transaction
        self.Approval = 'Null' #default at creation.  This is updated to call sig_app(Data, PatientAddress, RequestorAddress) from wallet when generating an approval_transaction
        self.TransactionHash = self.transaction_hash()

    """computing the Transaction hash"""

    def transaction_hash(self):
        string_to_hash = (
            str(self.VersionNumber) + str(self.PatientAddress) + str(self.VOAddress)
        )
        string_to_hash += str(self.HippaID)
        string_to_hash += str(self.SummaryAvail)
        string_to_hash += str(self.Data)
        string_to_hash += str(self.RequestorAddress)
        string_to_hash += str(self.Approval)
        bytes_to_hash = bytes(string_to_hash, "utf-8")
        return sha256(sha256(bytes_to_hash).hexdigest().encode("utf-8")).hexdigest()

    def printTransaction(self):
        print(f"Version Number is {self.VersionNumber}")
        print(f"Patient Address is {self.PatientAddress}")
        print(f"Verified Organisation Address is {self.VOAddress}")
        print(f"Hippa ID is {self.HippaID}")
        print(f"Summary Available is {self.SummaryAvail}")
        print(f"Data Pointer is {self.Data}")
        print(f"Requesting Address is {self.RequestorAddress}")
        print(f"Approving Signature is {self.Approval}")
        print(f"The Transaction Hash is {self.TransactionHash}")


"""creating the object to hold the Blockchain itself"""


class Blockchain:
    def __init__(self):
        self.blockchain = []  # my chain will be  alist of Blocks
        self.genesis_block()  # create the first block

    """building the Genesis block with Prev Hash 00000000000000000000"""

    def genesis_block(self):
        genesistransaction = Transaction(
            "Genesis Patient", "Genesis VO", 1, True, "Genesis Pointer"
        )
        genesisblock = Block([genesistransaction])
        genesisblock.hashPrevBlock = "00000000000000000000"
        self.blockchain.append(genesisblock)

    """add a new block to the Blockchain"""

    def add_block(self, Block):
        Block.BlockHeader.hashPrevBlock = self.blockchain[-1].Blockhash  # add the hash of the last Block to this latest block
        Block.mine_block(difficulty=4)
        #Block.Blockhash = (Block.block_hash())  # recompute the hash of the block with updated PrevHash
        self.blockchain.append(Block)  # add it to the end of the chain

    """you can search for a block by either 'height' or 'hash'.  This function will then call
    printBlock to display the results.  For height the input needs to be an integer greater than or equal to zero
    This is Function1 of the homework"""

    def search_block(self, type, input):
        if type == "height":
            if input < len(self.blockchain):
                self.blockchain[input].printBlock()
            elif input >= len(self.blockchain):
                print(
                    f"the blockchain is only of length {len(self.blockchain)} so it has max height {len(self.blockchain) - 1}"
                )
        elif type == "hash":
            counter = 0
            for i in range(len(self.blockchain)):
                if self.blockchain[i].Blockhash == input:
                    counter = 1
                    self.blockchain[i].printBlock()
            if counter == 0:
                print("There is no block with that hash")
        else:
            print(
                "you didnt enter a valid search parameter.  The arguments are: type (either 'height' or 'hash') and inputs (either the block height as an integer or block hash)"
            )

    """you can search for a Transaction by referencing its hash.  This is Function2 of the homework"""

    def search_transaction(self, hash):
        counter = 0
        for i in range(len(self.blockchain)):
            for j in range(len(self.blockchain[i].Transactions_input)):
                if self.blockchain[i].Transactions[j] == hash:
                    counter = 1
                    self.blockchain[i].Transactions_input[j].printTransaction()
        if counter == 0:
            print("There is no transaction with that hash")

    """you can search for transactions associated with a Patient Address.  This will return
    all the associated transactions.  This is also called by the function below
    print_patient_transactions()"""

    def search_patient_transactions(self, patient_add):
        patient_transacts = []
        for i in range(len(self.blockchain)):
            for j in range(len(self.blockchain[i].Transactions_input)):
                if (
                    self.blockchain[i].Transactions_input[j].PatientAddress
                    == patient_add
                ):
                    patient_transacts.append(self.blockchain[i].Transactions_input[j])
        return patient_transacts

    """you can print the details of all the transactions assocaiated with a Patient Address"""

    def print_patient_transactions(self, patient_add):
        patient_transacts = self.search_patient_transactions(patient_add)
        n = len(patient_transacts)
        print()
        print(f"There are {n} records for the patient with address {patient_add}")
        for i in range(n):
            print()
            print(f"Record {i+1} is")
            print()
            patient_transacts[i].printTransaction()

    """you can search for transactions associated with a Hippa ID.  This will return
    all the associated transactions.  This is also called by the function below
    print_hippa_summary()"""

    def search_hippa_transactions(self, hippa_ID):
        hippa_transacts = []
        for i in range(len(self.blockchain)):
            for j in range(len(self.blockchain[i].Transactions_input)):
                if self.blockchain[i].Transactions_input[j].HippaID == hippa_ID:
                    hippa_transacts.append(self.blockchain[i].Transactions_input[j])
        return hippa_transacts

    """you can print the summary details of all the transactions assocaiated with a given Hippa ID.
    This groups patients at the same VO together (sorted by VO) before printing"""

    def print_hippa_summary(self, hippa_ID):
        hippa_transacts = self.search_hippa_transactions(hippa_ID)
        n = len(hippa_transacts)
        print()
        print(
            f"There are {n} records for treatment associated with Hippa ID {hippa_ID}"
        )
        print()
        hippa_transacts.sort(key=lambda Transaction: Transaction.VOAddress)
        for i in range(n):
            print(
                f"VO ID is: {hippa_transacts[i].VOAddress}, Patient Address is {hippa_transacts[i].PatientAddress}, Summary Availability is {hippa_transacts[i].SummaryAvail}"
            )


class Wallet:
    def __init__(self, private_key_hex=None):
        if private_key_hex:
            self.private_key = bytes.fromhex(private_key_hex)
        else:
            self.private_key = os.urandom(32)
        self.steps = {}
        self.public_key = self.private_key_to_public_key()

    def sha256(self, data):
        return hashlib.sha256(data).digest()

    def ripemd160(self, data):
        h = hashlib.new("ripemd160")
        h.update(data)
        return h.digest()

    def base58_encode(self, data):
        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        base_count = len(alphabet)
        num = int.from_bytes(data, "big")
        encoded = ""
        while num > 0:
            num, rem = divmod(num, base_count)
            encoded = alphabet[rem] + encoded
        n_pad = len(data) - len(data.lstrip(b"\x00"))
        return "1" * n_pad + encoded

    def private_key_to_compressed_public_key(self):
        sk = ecdsa.SigningKey.from_string(self.private_key, curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        x = vk.to_string()[:32]
        y = vk.to_string()[32:]
        if int.from_bytes(y, "big") % 2 == 0:
            return b"\x02" + x
        else:
            return b"\x03" + x

    def private_key_to_public_key(self):
        sk = ecdsa.SigningKey.from_string(self.private_key, curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        return vk.to_string()

    def generate_address(self):

        compressed_public_key = self.private_key_to_compressed_public_key()

        sha256_pk = self.sha256(compressed_public_key)

        ripemd160_pk = self.ripemd160(sha256_pk)

        versioned_payload = b"\x00" + ripemd160_pk

        sha256_vp = self.sha256(versioned_payload)

        sha256_sha256_vp = self.sha256(sha256_vp)

        checksum = sha256_sha256_vp[:4]

        binary_address = versioned_payload + checksum

        bitcoin_address = self.base58_encode(binary_address)

    def print_steps(self):
        for stage, value in self.steps.items():
            print(f"{stage} is: {value}")

    @staticmethod
    def generate_shared_secret():
        return os.urandom(32)

    @staticmethod
    def aes_encrypt(shared_secret, data):
        iv = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(shared_secret), modes.CFB(iv), backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted_data = iv + encryptor.update(data.encode()) + encryptor.finalize()
        return base64.b64encode(encrypted_data).decode("utf-8")

    @staticmethod
    def aes_decrypt(shared_secret, encrypted_data):
        encrypted_data = base64.b64decode(encrypted_data)
        iv = encrypted_data[:16]
        cipher = Cipher(
            algorithms.AES(shared_secret), modes.CFB(iv), backend=default_backend()
        )
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
        return decrypted_data.decode("utf-8")

    def sign_message(self, message):
        sk = ecdsa.SigningKey.from_string(self.private_key, curve=ecdsa.SECP256k1)
        return base64.b64encode(sk.sign(message.encode())).decode("utf-8")

    def verify_message(self, public_key, message, signature):
        vk = ecdsa.VerifyingKey.from_string(public_key, curve=ecdsa.SECP256k1)
        try:
            return vk.verify(base64.b64decode(signature), message.encode())
        except ecdsa.BadSignatureError:
            return False


class Patient(Wallet):
    def create_token(self, requester_public_key, verified_authority_public_key):
        shared_secret = self.generate_shared_secret()

        encrypted_secret_for_requester = self.encrypt_shared_secret(
            requester_public_key, shared_secret
        )
        encrypted_secret_for_verified_authority = self.encrypt_shared_secret(
            verified_authority_public_key, shared_secret
        )

        token = {
            "encrypted_secret_for_requester": encrypted_secret_for_requester,
            "encrypted_secret_for_verified_authority": encrypted_secret_for_verified_authority,
            "expiration_time": (datetime.utcnow() + timedelta(days=1)).isoformat()
            + "Z",
        }

        token_json = json.dumps(token, indent=2)
        signature = self.sign_message(token_json)
        return token_json, signature

    @staticmethod
    def encrypt_shared_secret(public_key, shared_secret):
        encrypted_secret = public_key.encrypt(
            shared_secret,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return base64.b64encode(encrypted_secret).decode("utf-8")


class Requester(Wallet):
    def decrypt_token(self, token):
        decrypted_secret = self.decrypt_shared_secret(
            self.private_key, token["encrypted_secret_for_requester"]
        )
        return decrypted_secret

    @staticmethod
    def decrypt_shared_secret(private_key, encrypted_secret):
        decrypted_secret = private_key.decrypt(
            base64.b64decode(encrypted_secret),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return decrypted_secret


class VerifiedAuthority(Wallet):
    def decrypt_token(self, token):
        decrypted_secret = self.decrypt_shared_secret(
            self.private_key, token["encrypted_secret_for_verified_authority"]
        )
        return decrypted_secret

    @staticmethod
    def decrypt_shared_secret(private_key, encrypted_secret):
        decrypted_secret = private_key.decrypt(
            base64.b64decode(encrypted_secret),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return decrypted_secret

    def verify_patient_authority(self, patient_public_key, token_json, signature):
        return self.verify_message(patient_public_key, token_json, signature)


def load_public_key(pem_file):
    with open(pem_file, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    return public_key


def load_private_key(pem_file):
    with open(pem_file, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)
    return private_key


def load_transactions_from_csv(file_path):
    transactions = []
    with open(file_path, newline="") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            patient_address = row["patient_address"]
            vo_address = row["VO_address"]
            hippa_id = int(
                row["hippa_id"]
            )  # Assuming HIPAA ID is unique and can be mapped from 'id' column
            summary_available = row["gender"] in [
                "Male",
                "Female",
            ] 
            data_pointer = row["id"]
            #approval_signature = (
            #    "Signature_" + row["first_name"]
            #)
            transaction = Transaction(
                patient_address,
                vo_address,
                hippa_id,
                summary_available,
                data_pointer
            )
            transactions.append(transaction)
    return transactions


if __name__ == "__main__":
    transactions = load_transactions_from_csv("MOCK_DATA.csv")

    block_1 = Block(transactions[:5])
    block_2 = Block(transactions[5:10])

    b = Blockchain()
    b.add_block(block_1)
    b.add_block(block_2)

    print("\nHere is the block at height 1 in the Blockchain\n")

    b.search_block("height", 1)

    print("\nHere is a transaction searched by its hash\n")

    b.search_transaction(transactions[3].TransactionHash)

    print("\nPrinting all transactions associated with a given patient address")
    b.print_patient_transactions(transactions[0].PatientAddress)

    print("\nPrinting summary of transactions associated with a given HIPAA ID")
    b.print_hippa_summary(transactions[0].HippaID)
