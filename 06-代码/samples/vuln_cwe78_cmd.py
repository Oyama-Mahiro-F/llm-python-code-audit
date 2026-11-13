"""CWE-78 演示样本:OS 命令注入(外部输入拼进系统命令)。"""
import os


def run_command(user_cmd):
    command = "ls " + user_cmd
    os.system(command)
    return 0
