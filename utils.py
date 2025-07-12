import os
print(os.system("df -h"))

print(os.system("free -h"))

print(os.system("uptime"))

def run_command(cmd):
    return os.system(cmd)

run_command("date")