"""CWE-22 演示样本:路径穿越(外部输入拼进文件路径)。"""


def read_file(user_path):
    path = "/var/data/" + user_path
    with open(path) as f:
        return f.read()
