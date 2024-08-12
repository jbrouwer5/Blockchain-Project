import health_service_pb2
from problem2 import Transaction, PatientDB, Patient, Block, Header

def to_proto_transaction(transaction):
    
    newTransaction = health_service_pb2.Transaction()
               
    newTransaction.VersionNumber = transaction.VersionNumber
    newTransaction.Patient_Ad = transaction.PatientAddress
    newTransaction.VOAddress = transaction.VOAddress
    newTransaction.HippaID = transaction.HippaID
    newTransaction.SummaryAvail = transaction.SummaryAvail
    newTransaction.Data = transaction.Data
    newTransaction.RequestorAddress = transaction.RequestorAddress
    newTransaction.Approval = transaction.Approval
    newTransaction.TransactionHash = transaction.TransactionHash

    proto_patient_db = health_service_pb2.patientDB()

    # Assuming patient_db is a list of patient instances
    for patient in transaction.patient_db.pdb:
        newPatient = health_service_pb2.patient()
        newPatient.first_name = patient[1].first_name
        newPatient.last_name = patient[1].last_name
        newPatient.email = patient[1].email
        proto_patient_db.patients.append(newPatient)

    newTransaction.patient_db.CopyFrom(proto_patient_db)

    return newTransaction

def from_proto_transaction(proto_transaction):
    # Assuming that the Transaction object has a similar structure
    transaction = Transaction()
    
    transaction.VersionNumber = proto_transaction.VersionNumber
    transaction.PatientAddress = proto_transaction.Patient_Ad
    transaction.VOAddress = proto_transaction.VOAddress
    transaction.HippaID = proto_transaction.HippaID
    transaction.SummaryAvail = proto_transaction.SummaryAvail
    transaction.Data = proto_transaction.Data
    transaction.RequestorAddress = proto_transaction.RequestorAddress
    transaction.Approval = proto_transaction.Approval
    transaction.TransactionHash = proto_transaction.TransactionHash

    # Assuming that the patient_db is a list of patient instances in the Transaction class
    transaction.patient_db = PatientDB()
    for proto_patient in proto_transaction.patient_db.patients:
        patient = Patient()
        patient.first_name = proto_patient.first_name
        patient.last_name = proto_patient.last_name
        patient.email = proto_patient.email
        transaction.patient_db.pdb.append(patient)

    return transaction

def to_proto_block(block):
    new_block = health_service_pb2.Block()
    
    new_block.MagicNumber = block.MagicNumber
    new_block.Blocksize = block.Blocksize
    
    for transaction in block.Transactions_input:
        proto_transaction = to_proto_transaction(transaction)
        new_block.Transactions_input.append(proto_transaction)
    
    for transaction_hash in block.Transactions:
        new_block.Transactions.append(transaction_hash)
    
    new_block.TransactionCounter = block.TransactionCounter
    
    new_block.BlockHeader.CopyFrom(to_proto_header(block.BlockHeader))
    
    new_block.Blockhash = block.Blockhash
    
    return new_block

def to_proto_header(header):
    new_header = health_service_pb2.Header()
    
    for transaction_hash in header.Block_Transactions:
        new_header.Block_Transactions.append(transaction_hash)
    
    new_header.Version = header.Version
    new_header.hashPrevBlock = header.hashPrevBlock
    
    for merkle_hash in header.MerkleTree:
        new_header.MerkleTree.extend(merkle_hash)
    
    new_header.Timestamp = header.Timestamp
    new_header.Bits = header.Bits
    new_header.Nonce = header.Nonce
    
    return new_header

def from_proto_block(proto_block):
    # Converting Transactions_input
    transactions_input = [from_proto_transaction(t) for t in proto_block.Transactions_input]
    
    # Creating the Block object
    block = Block(transactions_input)
    
    block.MagicNumber = proto_block.MagicNumber
    block.Blocksize = proto_block.Blocksize
    
    # Converting Transactions
    block.Transactions = [t for t in proto_block.Transactions]
    
    block.TransactionCounter = proto_block.TransactionCounter
    
    # Converting BlockHeader
    block.BlockHeader = from_proto_header(proto_block.BlockHeader)
    
    block.Blockhash = proto_block.Blockhash
    
    return block

def from_proto_header(proto_header):
    # Converting Block_Transactions
    block_transactions = [t for t in proto_header.Block_Transactions]
    
    # Creating the Header object
    header = Header(block_transactions)
    
    header.Version = proto_header.Version
    header.hashPrevBlock = proto_header.hashPrevBlock
    
    header.MerkleTree = [list(merkle_hash) for merkle_hash in proto_header.MerkleTree]
    
    header.Timestamp = proto_header.Timestamp
    header.Bits = proto_header.Bits
    header.Nonce = proto_header.Nonce
    
    return header
