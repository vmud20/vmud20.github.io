import os
import json
import sys

def getcveNum(signaturePath_org, signaturePath_rep):
    sigNum = {}
    allNum = 0
    for cve in os.listdir(signaturePath_rep):
        with open(os.path.join(signaturePath_org, cve),"r") as f:
            sigs = json.load(f)
            fp = open(os.path.join(signaturePath_rep, cve),"r")
            sigs_new = json.load(fp)
            fp.close()
            if max(len(sigs.keys()), len(sigs_new.keys())) <= 1:
                continue
            sigNum[cve.replace(".json","")] = max(len(sigs.keys()), len(sigs_new.keys()))
            allNum += 1

    cve_method = {}
    for cve in sigNum.keys():
        if sigNum[cve] > 10:
            if "10+" not in cve_method.keys():
                cve_method["10+"] = 0
            cve_method["10+"] += 1
        else:
            if sigNum[cve] not in cve_method.keys():
                cve_method[sigNum[cve]] = 0
            cve_method[sigNum[cve]] += 1
    
    with open("data/cve_method.json","w") as f:
        json.dump(cve_method,f)

if __name__ == "__main__":
    signaturePath_org = sys.argv[1]
    signaturePath_rep = sys.argv[2]
    print(signaturePath_org, signaturePath_rep)
    getcveNum(signaturePath_org, signaturePath_rep)