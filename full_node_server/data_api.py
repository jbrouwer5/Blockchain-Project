import pandas as pd 
# functions for loading data from csv mock database 

def load_data(file_path):
    df = pd.read_csv(file_path) 
    return df

def query_data(id, data):
    return data.iloc[id]

if __name__ == "__main__":
    file_path = "MOCK_DATA.csv"
    data = load_data(file_path)
    row = query_data(5, data)
    print(row)





