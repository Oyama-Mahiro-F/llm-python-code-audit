def read_file(user_path):
    path = "/var/data/" + user_path
    with open(path) as f:
        return f.read()
