import hashlib

def hash_data(data):
    # Broken Crypto Algorithm [CWE-327]
    md5 = hashlib.md5()
    md5.update(data.encode('utf-8'))
    return md5.hexdigest()
