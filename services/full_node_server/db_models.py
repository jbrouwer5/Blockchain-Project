from sqlalchemy import create_engine, Column, Integer, String, Sequence, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()

# ID (this is a unique integer for each record).  This will be encrypted in the Pointer function and stored in the Transaction as the unique reference to this medical record

# first_name (string).  Used in the generation of the unique blockchain address for each patient

# Last_name (string).  Used in the generation of the unique blockchain address for each patient

# email (string). Used in the generation of the unique blockchain address for each patient

# gender (string).  No use in blockchain currently

# height (float) in inches. No use in blockchain currently

# weight (integer) in lbs.  No use in blockchain currently

# age (integer) in years.  No use in blockchain currently

# HippaID (integer).  Each integer represents a distinct treatment/type of medical record, eg, 27 = breast cancer scan etc

# patient_address (double sha256 hash).  This is the double sha256 of the concatenation of first_name, last_name, email

# VO_address (double_sha256 hash).  This is the double sha256 of the VO name


class HealthRecords(Base):
    __tablename__ = "health_records"
    id = Column(Integer, primary_key=True, autoincrement=True)
    first_name = Column(String)
    last_name = Column(String)
    email = Column(String)
    gender = Column(String)
    height = Column(Float)
    weight = Column(Float)
    age = Column(Integer)
    HippaID = Column(Integer)
    patient_address = Column(String(64))
    vo_address = Column(String(64))


engine = create_engine("sqlite:///health_records.db")
Session = sessionmaker(bind=engine)
Base.metadata.create_all(engine)
