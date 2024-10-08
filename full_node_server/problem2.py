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
from wallet import Wallet, Patient, Requester, VerifiedAuthority


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
    def __init__(self, Patient_Ad, VO_Ad, H_ID, Summ_Av, Pointer, Patient_DB):
        self.VersionNumber = 1 #default
        self.PatientAddress = Patient_Ad #input from database at creation
        self.VOAddress = VO_Ad #input from databse at creation
        self.HippaID = H_ID #input from database at creation
        self.SummaryAvail = True #default
        self.Data = Pointer #need to call pointer(database_ID, PatientAddress, VOAddress) from Wallet
        self.RequestorAddress = 'Null' #default at creation.  This is updated to RequestorAddress when generating an aaproval_transaction
        self.Approval = 'Null' #default at creation.  This is updated to call sig_app(Data, PatientAddress, RequestorAddress) from wallet when generating an approval_transaction
        self.TransactionHash = self.transaction_hash()
        self.patient_db = Patient_DB

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

    def req_approval(self, requestor):
        self.RequestorAddress = requestor.address
        n = len(self.patient_db.pdb)
        for i in range(n):
            if self.patient_db.pdb[i][0] == self.PatientAddress:
                index = i
        patient = self.patient_db.pdb[index][1]
        self.Approval = patient.app_sig(self.Data, requestor.rsa_public_key)
        self.TransactionHash = self.transaction_hash()

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
    def __init__(self, patient_db):
        self.blockchain = []  # my chain will be  alist of Blocks
        self.patient_db = patient_db
        self.genesis_block()  # create the first block
        

    """building the Genesis block with Prev Hash 00000000000000000000"""

    def genesis_block(self):
        genesistransaction = Transaction(
            "Genesis Patient", "Genesis VO", 1, True, "Genesis Pointer", self.patient_db
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

"""creating a Patient DB to hold all Patient Wallet objects, referenced by their patient_address.
This would be created locally for each patient, here i am creating a master database as the GUI interfaces
for multiple patients to independently access the blockchain is not in this phase"""
class PatientDB:
    def __init__(self):
        self.pdb = []  # my db will be a list of lists, for each sub_list: list[0] = patient_address, list[1] = Patient Wallet object
        
        
    def add_patient(self, first_name, last_name, email, Patient_Ad):
        patient = Patient(first_name, last_name, email)
        self.pdb.append([Patient_Ad, patient])  # add the list to the end of the chain


def load_public_key(pem_file):
    with open(pem_file, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    return public_key


def load_private_key(pem_file):
    with open(pem_file, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)
    return private_key


def load_transactions_from_csv(file_path, patient_db, vo):
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
            raw_pointer = row["id"]
            #now i will check if we already have a Patient Wallet object for this patient, and if not create one
            n = len(patient_db.pdb)
            if n == 0:
                patient_db.add_patient(row["first_name"], row["last_name"], row["email"], patient_address)
                index = 0
            else:
                flag = 0
                for i in range(n):
                    if patient_db.pdb[i][0] == patient_address:
                        index = i
                        flag = 1
                if flag == 0:
                    patient_db.add_patient(row["first_name"], row["last_name"], row["email"], patient_address)
                    index = n
            #call the correct patient wallet object for this patient
            patient = patient_db.pdb[index][1]
            #encrypt the pointer with their public key
            data_pointer = patient.pointer(int(raw_pointer), vo.rsa_public_key)

            #build the transaction
            transaction = Transaction(
                patient_address,
                vo_address,
                hippa_id,
                summary_available,
                data_pointer, 
                patient_db
            )
            transactions.append(transaction)
    return transactions


# if __name__ == "__main__":
#     #first create an instance of the patient database to hole PatientWallet objects
#     self.patient_db = PatientDB()
#     #in this version we are just creating 1 VO object
#     vo = VerifiedAuthority()
#     #and also only 1 requestor for approval
#     requester = Requester()
#     #build transactions from the csv file
#     transactions = load_transactions_from_csv("MOCK_DATA.csv")

#     block_1 = Block(transactions[:5])
#     block_2 = Block(transactions[5:10])

#     b = Blockchain()
#     b.add_block(block_1)
#     b.add_block(block_2)

#     #print("\nHere is the block at height 1 in the Blockchain\n")

#     #b.search_block("height", 1)

#     #print("\nHere is a transaction searched by its hash\n")

#     #b.search_transaction(transactions[3].TransactionHash)

#     print("\nPrinting all transactions associated with a given patient address")
#     b.print_patient_transactions(transactions[0].PatientAddress)

#     #print("\nPrinting summary of transactions associated with a given HIPAA ID")
#     #b.print_hippa_summary(transactions[0].HippaID)

#     print("\nTesting the app_sig function")
#     print("\nFirst search for the transactions with Hippa ID 103 (the first one is the one that has just been printed to the terminal)")
#     hippa103 = b.search_hippa_transactions(103)
#     print("\ntake that tx and lets simulate a patient giving approval to the requestor")
#     #first i create a new Transaction as i dont want to amend the original, but it replicates all the original fields
#     approval_tx = Transaction(hippa103[0].PatientAddress, hippa103[0].VOAddress, hippa103[0].HippaID, hippa103[0].SummaryAvail, hippa103[0].Data)
#     #then we add the 2 new fields and rehash it to complete the approved transaction
#     approval_tx.req_approval(requester)
#     print("\nprint the new updated transaction with new RequestorAddress, Approval and Hash\n")
#     approval_tx.printTransaction()
#     print("\nnow lets confirm it returns the correct database id from the MOCK_DATA.csv\n")
#     vo_submission = requester.requestor_generate(approval_tx.Approval)
#     retrieved_record_id = vo.vo_verify(vo_submission)
#     print("Retrieved Record ID:", retrieved_record_id)
