from hashlib import sha256
from datetime import datetime
from binascii import unhexlify, hexlify

"""creating the class object to hold the Blocks"""
class Block:
    def __init__(self, Transactions):
        self.MagicNumber = '0xD984BEF9' #default
        self.Blocksize = 0 #default
        self.Transactions_input = Transactions #this is a list of the Transactions that are input at creation
        self.Transactions = self.get_transactions() #i want to store the transactions by their hashes
        self.TransactionCounter = len(self.Transactions) #set to be the number of transactions in the block
        self.BlockHeader = Header(self.Transactions) #this is the Header object that is initiatied when the Block is created
        self.Blockhash = self.block_hash() #the double sha hash of this block
       

    def get_transactions(self):
        transaction_hashes = []
        for t in range(len(self.Transactions_input)):
            transaction_hashes.append(self.Transactions_input[t].TransactionHash)
        return transaction_hashes

    """creating the double sha hash representing this block, incorporating data from the Block's Header"""
    def block_hash(self):
        string_to_hash = str(self.BlockHeader.Timestamp) + str(self.BlockHeader.hashMerkleRoot) + str(self.BlockHeader.Bits)
        string_to_hash += str(self.BlockHeader.Nonce)
        string_to_hash += str(self.BlockHeader.hashPrevBlock)
        bytes_to_hash = bytes(string_to_hash, "utf-8")
        return sha256(sha256(bytes_to_hash).hexdigest().encode("utf-8")).hexdigest()

    def printBlock(self):
        print(f"Magic Number is f{self.MagicNumber}")
        print(f"Block Size is {self.Blocksize}")
        print(f"Block Header is {self.BlockHeader}")
        print(f"Transaction Counter is {self.TransactionCounter}")
        l = len (self.Transactions)
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
        self.hashPrevBlock = 'Unattached to Blockchain' #initiated as an unattached block, will change if it joins the Blockchain
        self.MerkleTree = self.make_merkle_tree() # Merkle Tree of the transactions in the Block
        #because i am not building a Merkle Tree if there is only 1 transaction I have different forms of output
        #hence the if statement to parse that (rather than make the 1 transaction case more complicated)
        if len(self.MerkleTree) == 1:
            self.hashMerkleRoot = self.MerkleTree[-1][0]
        else:
            self.hashMerkleRoot = self.MerkleTree[-1][0].decode("utf-8") # Merkle Root of the transactions in the Block
        self.Timestamp = int(round(datetime.now().timestamp())) #time the block is created (as an integer)
        self.Bits = 0 #default
        self.Nonce = 0 #default

    """re-using my Merkle Root code from Lab 4, so i kept the hexilify/unhexilify for the big/little endian
    management in this code to generate the merkle root"""
    def make_merkle_tree(self):
        #i have to create an empty list and iterate the hashes into it, as if i just take the hashes directly
        #the calculations below impact my original transacion list
        tx_list = []
        merkle_tree_hashes = []
        for tx in range(len(self.Block_Transactions)):
            tx_list.append(self.Block_Transactions[tx])
        #end of that set up process
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
            for i in range(int(len(tx_list)/2)):
                left = tx_list[i*2]
                right = tx_list[i*2+1]
                sha_left_to_bytes = unhexlify(left)[::-1]  
                sha_right_to_bytes = unhexlify(right)[::-1]
                root_temp = hexlify(sha256(sha256(sha_left_to_bytes + sha_right_to_bytes).digest()).digest()[::-1])
                new_tx_list.append(root_temp)
            counter +=1
            tx_list = new_tx_list
        merkle_tree_hashes.append([root_temp])
        return merkle_tree_hashes   
        #return root_temp.decode("utf-8")

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
    def __init__(self, Patient_Ad, VO_Ad, H_ID, Summ_Av, Pointer, App_Sig):
        self.VersionNumber = 1 #default
        self.PatientAddress = Patient_Ad #input at creation
        self.VOAddress = VO_Ad #input at creation
        self.HippaID = H_ID #input at creation
        self.SummaryAvail = Summ_Av #input at creation
        self.Data = Pointer #input at creation
        self.RequestorAddress = 'Null' #default
        self.Approval = App_Sig #input at creation
        self.TransactionHash = self.transaction_hash()

    """computing the Transaction hash"""
    def transaction_hash(self):
        string_to_hash = str(self.VersionNumber) + str(self.PatientAddress) +str(self.VOAddress)
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
        self.blockchain = [] # my chain will be  alist of Blocks
        self.genesis_block() #create the first block

    """building the Genesis block with Prev Hash 00000000000000000000"""    
    def genesis_block(self):
        genesistransaction = Transaction("Genesis Patient", "Genesis VO", 1, True, "Genesis Pointer", "Genesis Sig")
        genesisblock = Block([genesistransaction])
        genesisblock.hashPrevBlock = "00000000000000000000"
        self.blockchain.append(genesisblock)

    """add a new block to the Blockchain"""
    def add_block(self, Block):
        Block.BlockHeader.hashPrevBlock = self.blockchain[-1].Blockhash #add the hash of the last Block to this latest block
        Block.Blockhash = Block.block_hash() #recompute the hash of the block with updated PrevHash
        self.blockchain.append(Block) #add it to the end of the chain

    """you can search for a block by either 'height' or 'hash'.  This function will then call 
    printBlock to display the results.  For height the input needs to be an integer greater than or equal to zero
    This is Function1 of the homework"""
    def search_block(self, type, input):
        if type == 'height':
            if input < len(self.blockchain):
                self.blockchain[input].printBlock()
            elif input >= len(self.blockchain):
                print(f"the blockchain is only of length {len(self.blockchain)} so it has max height {len(self.blockchain) - 1}")
        elif type == 'hash':
            counter = 0
            for i in range(len(self.blockchain)):
                if self.blockchain[i].Blockhash == input:
                    counter = 1
                    self.blockchain[i].printBlock()
            if counter == 0:
                print("There is no block with that hash")
        else:
            print("you didnt enter a valid search parameter.  The arguments are: type (either 'height' or 'hash') and inputs (either the block height as an integer or block hash)")

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
                if self.blockchain[i].Transactions_input[j].PatientAddress == patient_add:
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
        print(f"There are {n} records for treatment associated with Hippa ID {hippa_ID}")
        print()
        hippa_transacts.sort(key=lambda Transaction: Transaction.VOAddress)
        for i in range(n):
            print(f"VO ID is: {hippa_transacts[i].VOAddress}, Patient Address is {hippa_transacts[i].PatientAddress}, Summary Availability is {hippa_transacts[i].SummaryAvail}")



"""run the program with the 10 hard coded transations
I then create 2 blocks with 5 transaction each and add these as the
first 2 blocks in my Blockchain"""
if __name__ == "__main__":
    t_1 = Transaction("Patient_Add_1", "VO_Add_1", 5, True, "Pointer1", "Patient_Sig_1")
    t_2 = Transaction("Patient_Add_2", "VO_Add_2", 25, True, "Pointer2", "Patient_Sig_2")
    t_3 = Transaction("Patient_Add_3", "VO_Add_1", 14, False, "Pointer3", "Patient_Sig_3")
    t_4 = Transaction("Patient_Add_4", "VO_Add_3", 234, True, "Pointer4", "Patient_Sig_4")
    t_5 = Transaction("Patient_Add_5", "VO_Add_4", 13245, False, "Pointer5", "Patient_Sig_5")
    t_6 = Transaction("Patient_Add_6", "VO_Add_1", 17, True, "Pointer6", "Patient_Sig_6")
    t_7 = Transaction("Patient_Add_2", "VO_Add_2", 14, True, "Pointer7", "Patient_Sig_2")
    t_8 = Transaction("Patient_Add_7", "VO_Add_5", 14, False, "Pointer8", "Patient_Sig_7")
    t_9 = Transaction("Patient_Add_1", "VO_Add_6", 134, True, "Pointer9", "Patient_Sig_1")
    t_10 = Transaction("Patient_Add_2", "VO_Add_1", 14, True, "Pointer10", "Patient_Sig_2")

    block_1 = Block([t_1, t_2, t_3, t_4, t_5])
    block_2 = Block([t_6, t_7, t_8, t_9, t_10])
    #block_1.printBlock()
    #block_2.printBlock()
    #print(block_1.BlockHeader.MerkleTree)
    #print(block_1.BlockHeader.hashMerkleRoot)
    #print(block_1.BlockHeader.hashPrevBlock)
    #t_4.printTransaction()

    b = Blockchain()
    b.add_block(block_1)
    b.add_block(block_2)

    """search for a block by block height"""
    print()
    print("Here is the block at height 1 in the Blockchain")
    print()
    b.search_block('height', 1)

    """search for a transaction by its hash"""
    print()
    print("here is transacton t_4, searched for by its hash")
    print()
    b.search_transaction(t_4.TransactionHash)

    """print all the transactions asscoiated with a given patient address"""
    b.print_patient_transactions("Patient_Add_1")

    """print all the transactions asscoiated with a given Hippa ID"""
    b.print_hippa_summary(14)