import pickle

def load_data(serialized_data):
    # Insecure Deserialization [CWE-502]
    obj = pickle.loads(serialized_data)
    return obj
