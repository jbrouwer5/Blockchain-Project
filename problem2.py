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
class Transaction:
    def __init__(self, ListOfInputs, ListOfOutputs):
        self.VersionNumber = 1 #default
        self.ListOfInputs = ListOfInputs #this list is input at creation
        self.InCounter = len(self.ListOfInputs) #i set this to be the number of distinct inputs
        self.ListOfOutputs = ListOfOutputs #this list is input at creation
        self.OutCounter = len(self.ListOfOutputs) #i set this to be the number of distinct outputs
        self.TransactionHash = self.transaction_hash()

    """computing the Transaction hash"""
    def transaction_hash(self):
        string_to_hash = str(self.VersionNumber) + str(self.InCounter)
        for i in range(len(self.ListOfInputs)):
            string_to_hash += str(self.ListOfInputs[i])
        string_to_hash += str(self.OutCounter)
        for i in range(len(self.ListOfOutputs)):
            string_to_hash += str(self.ListOfOutputs[i])
        bytes_to_hash = bytes(string_to_hash, "utf-8")
        return sha256(sha256(bytes_to_hash).hexdigest().encode("utf-8")).hexdigest()

    def printTransaction(self):
        print(f"Version Number is {self.VersionNumber}")
        print(f"In Counter is {self.InCounter}")
        l_i = len(self.ListOfInputs)
        print(f"There are {l_i} inputs and the List of Inputs is:")
        for i in range(l_i):
            print(self.ListOfInputs[i])
        print(f"Out Counter is {self.OutCounter}")
        l_o = len(self.ListOfOutputs)
        print(f"There are {l_o} outputs and the List of Outputs is:")
        for i in range(l_o):
            print(self.ListOfOutputs[i])
        print(f"The Transaction Hash is {self.TransactionHash}")

"""creating the object to hold the Blockchain itself"""
class Blockchain:
    def __init__(self):
        self.blockchain = [] # my chain will be  alist of Blocks
        self.genesis_block() #create the first block

    """building the Genesis block with Prev Hash 00000000000000000000"""    
    def genesis_block(self):
        genesistransaction = Transaction(["this is the only transaction in the genesis block"], ["created by MarkS"])
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

"""run the program with the 10 hard coded transations
I then create 2 blocks with 5 transaction each and add these as the
first 2 blocks in my Blockchain"""
if __name__ == "__main__":
    t_1 = Transaction(["aaa"], ["bbb"])
    t_2 = Transaction(["aaa"], ["ccc"])
    t_3 = Transaction(["aaa"], ["ddd"])
    t_4 = Transaction(["aaa"], ["eee"])
    t_5 = Transaction(["aaa"], ["fff"])
    t_6 = Transaction(["zzz"], ["bbb"])
    t_7 = Transaction(["zzz"], ["ccc"])
    t_8 = Transaction(["zzz"], ["ddd"])
    t_9 = Transaction(["zzz"], ["eee"])
    t_10 = Transaction(["zzz"], ["fff"])

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
    b.search_transaction('967a2ea00e4a820beafdcf6674917aa77124e384017aed35f0d7b6b5aa1e6cde')

    #print(b.blockchain[0].hashPrevBlock)
    #b.search_block('height', 0)
    #b.search_block('hash', block_1.Blockhash)
    #b.search_block('hash', "tttttttt")
    #b.search_transaction('967a2ea00e4a820beafdcf6674917aa77124e384017aed35f0d7b6b5aa1e6cde')
    #b.search_transaction(t_4.TransactionHash)
    #b.search_transaction("eeeee")

