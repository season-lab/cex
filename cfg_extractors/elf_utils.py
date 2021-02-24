import subprocess

def check_pie(binary):
    file_output = subprocess.check_output(["file", binary])
    if b"LSB shared object" in file_output or b"LSB pie executable" in file_output:
        return True
    return False
