import hashlib
import rzpipe

def check_pie(binary):
    rz  = rzpipe.open(binary, flags=["-2"])
    res = rz.cmdj("iIj")
    if "pic" in res:
        res = res["pic"]
    else:
        res = res["PIE"]
    rz.quit()
    return res

def get_md5_file(filename):
    with open(filename,'rb') as f_binary:
        md5 = hashlib.md5(f_binary.read()).hexdigest()
    return md5
