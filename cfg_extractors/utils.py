import subprocess
import hashlib

def check_pie(binary):
    file_output = subprocess.check_output(["file", binary])
    if b"LSB shared object" in file_output or b"LSB pie executable" in file_output:
        return True
    return False

def get_md5_file(filename):
    with open(filename,'rb') as f_binary:
        md5 = hashlib.md5(f_binary.read()).hexdigest()
    return md5
