def run_command(user_cmd):
    command = "ls " + user_cmd
    os.system(command)
    return 0
