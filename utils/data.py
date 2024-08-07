import pandas as pd
import hashlib


def double_sha256(data):
    data = data.encode("utf-8")
    return hashlib.sha256(hashlib.sha256(data).digest()).hexdigest()


df = pd.read_csv("../MOCK_DATA.csv")


# Apply the concatenation and hashing
df["patient_blockchain_address"] = df.apply(
    lambda row: double_sha256(row["first_name"] + row["last_name"] + row["email"]),
    axis=1,
)

# Display the updated DataFrame
print(df)
df.to_csv("MOCK_DATA.csv", index=False)
