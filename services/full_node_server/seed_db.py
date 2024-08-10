import csv
from db_models import HealthRecord, Session


def seed_database(csv_file_path):
    # Create a session
    session = Session()

    # Open the CSV file
    with open(csv_file_path, newline="") as csvfile:
        reader = csv.DictReader(csvfile)

        # Iterate over the rows in the CSV
        for row in reader:
            # Create a new HealthRecords object

            record = HealthRecord(
                id=int(row["id"]),
                first_name=row["first_name"],
                last_name=row["last_name"],
                email=row["email"],
                gender=row["gender"],
                height=float(row["height"]),
                weight=float(row["weight"]),
                age=int(row["age"]),
                hippa_id=int(row["Hippa_ID"]),
                vo_address=row["VO_address"],
                patient_address=row["patient_address"],
            )

            # Add the record to the session
            session.add(record)

        # Commit the session to save all users to the database
        session.commit()

    # Close the session
    session.close()
    print(f"Database seeded with data from {csv_file_path}")


if __name__ == "__main__":
    # Seed the database with data from users.csv
    seed_database("data/uchicago.csv")
