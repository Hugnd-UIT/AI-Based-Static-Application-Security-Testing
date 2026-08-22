def read_file(filename):
    # Path Traversal [CWE-22]
    path = "/var/www/uploads/" + filename
    with open(path, 'r') as f:
        data = f.read()
    return data
