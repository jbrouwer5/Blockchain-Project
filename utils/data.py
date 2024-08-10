import pandas as pd
import hashlib
import os
from pathlib import Path


def double_sha256(data):
    data = data.encode("utf-8")
    return hashlib.sha256(hashlib.sha256(data).digest()).hexdigest()


data_dir = Path(os.path.dirname("../data/"))


for file in data_dir.glob("*.csv"):
    df = pd.read_csv(file)
    base_name = file.stem

    df["patient_address"] = df.apply(
        lambda row: double_sha256(row["first_name"] + row["last_name"] + row["email"]),
        axis=1,
    )

    df["VO_address"] = df.apply(
        lambda row: double_sha256(str(base_name)),
        axis=1,
    )

    updated_file_path = data_dir / f"{base_name}.csv"
    df.to_csv(updated_file_path, index=False)
    print(f"Updated {file} and saved to {updated_file_path}")
