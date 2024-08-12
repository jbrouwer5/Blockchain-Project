import pytest
import csv
from hashlib import sha256
from problem2 import Transaction

@pytest.fixture
def transactions_from_csv():
    csv_data = """id,first_name,last_name,email,gender,height,weight,age
1,Katti,Lathaye,klathaye0@hc360.com,Female,77.2,90,24
2,Ely,Boutflour,eboutflour1@cargocollective.com,Non-binary,57.3,166,34
3,Josefina,Hamer,jhamer2@sitemeter.com,Female,59.9,243,34
4,Uri,McGurn,umcgurn3@miitbeian.gov.cn,Male,59,107,43
5,Henry,O'Hartigan,hohartigan4@ihg.com,Male,70.3,157,24
6,Tamqrah,Poetz,tpoetz5@imgur.com,Bigender,59.8,185,38
7,Ethelbert,Dudny,edudny6@state.tx.us,Male,57.9,99,20
8,Aymer,Sjollema,asjollema7@zimbio.com,Male,65.3,97,46
9,Ruttger,Rizzetti,rrizzetti8@printfriendly.com,Male,65.9,129,41"""
    transactions = []
    reader = csv.DictReader(csv_data.splitlines())
    for row in reader:
        patient_address = row['first_name'] + "_" + row['last_name']
        vo_address = row['email']
        hippa_id = int(row['id'])
        summary_available = row['gender'] not in ['Non-binary', 'Bigender']
        data_pointer = row['email']
        approval_signature = 'Signature_' + row['first_name']
        transaction = Transaction(patient_address, vo_address, hippa_id, summary_available, data_pointer, approval_signature)
        transactions.append(transaction)
    return transactions

def test_transaction_initialization(transactions_from_csv):
    for transaction in transactions_from_csv:
        assert transaction.VersionNumber == 1
        assert transaction.PatientAddress == transaction.PatientAddress
        assert transaction.VOAddress == transaction.VOAddress
        assert transaction.HippaID == int(transaction.HippaID)
        assert transaction.SummaryAvail == (transaction.SummaryAvail in ['Male', 'Female'])
        assert transaction.Data == transaction.Data
        assert transaction.RequestorAddress == "Null"
        assert transaction.Approval == transaction.Approval

def test_transaction_hash(transactions_from_csv):
    for transaction in transactions_from_csv:
        string_to_hash = (
            str(transaction.VersionNumber)
            + str(transaction.PatientAddress)
            + str(transaction.VOAddress)
            + str(transaction.HippaID)
            + str(transaction.SummaryAvail)
            + str(transaction.Data)
            + str(transaction.RequestorAddress)
            + str(transaction.Approval)
        )
        bytes_to_hash = bytes(string_to_hash, "utf-8")
        expected_hash = sha256(sha256(bytes_to_hash).hexdigest().encode("utf-8")).hexdigest()
        assert transaction.TransactionHash == expected_hash

def test_print_transaction(transactions_from_csv, capsys):
    for transaction in transactions_from_csv:
        transaction.printTransaction()
        captured = capsys.readouterr()
        assert f"Version Number is {transaction.VersionNumber}" in captured.out
        assert f"Patient Address is {transaction.PatientAddress}" in captured.out
        assert f"Verified Organisation Address is {transaction.VOAddress}" in captured.out
        assert f"Hippa ID is {transaction.HippaID}" in captured.out
        assert f"Summary Available is {transaction.SummaryAvail}" in captured.out
        assert f"Data Pointer is {transaction.Data}" in captured.out
        assert f"Requesting Address is {transaction.RequestorAddress}" in captured.out
        assert f"Approving Signature is {transaction.Approval}" in captured.out
        assert f"The Transaction Hash is {transaction.TransactionHash}" in captured.out
