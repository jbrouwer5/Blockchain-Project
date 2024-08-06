import pandas as pd 

def load_data(file_path):
    df = pd.read_csv(file_path) 
    return df

def query_data(id, data):
    return data.iloc[id]

# verified_authority_index is 1 or 2
# patient id ranges from 0-999 for both
def get_patient_data(verified_authority_index, patient_id):
    data = load_data("VA" + str(verified_authority_index) + "_MOCK_DATA.csv")
    patient_data = query_data(patient_id, data)
    return patient_data
    
if __name__ == "__main__":
    print(get_patient_data(1, 10))





