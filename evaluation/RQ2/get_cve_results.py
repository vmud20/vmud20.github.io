import pandas as pd
import ast
import json
import os
import pickle


f = open("thrown_cve.pkl","rb")
thrown_cve = pickle.load(f)
f.close()


def getcveResults():
    GTData = pd.read_csv("../RQ1/results/GT.csv", encoding='utf-8')
    signaturePath = "../../dataset/signature_org/"
    signaturePath_new = "../../dataset/signature_rep/"
    sigNum = {"CVE-2022-36123":2}
    for cve in os.listdir(signaturePath_new):
        with open(signaturePath + cve,"r") as f:
            sigs = json.load(f)
            fp = open(signaturePath_new + cve,"r")
            sigs_new = json.load(fp)
            fp.close()
            sigNum[cve.replace(".json","")] = max(len(sigs.keys()), len(sigs_new.keys()))
    repos = {}
    repoNames = []
    for index, row in GTData.iterrows():
        if row['CVE-ID'] in thrown_cve:
            continue
        # if row['CVE-ID'] not in sigNum.keys():
        #     continue
        if sigNum[row['CVE-ID']] not in repos.keys():
            repos[sigNum[row['CVE-ID']]] = []
        repos[sigNum[row['CVE-ID']]].append(row.to_dict())
    
    repoTP = {}
    for index, row in GTData.iterrows(): 
        if row['CVE-ID'] in thrown_cve:
            continue
        # if row['CVE-ID'] not in sigNum.keys():
        #     continue
        if sigNum[row['CVE-ID']] not in repoTP.keys():
            repoTP[sigNum[row['CVE-ID']]] = 0
        if row['result'] == "TP":
            repoTP[sigNum[row['CVE-ID']]] += 1

    dataframe_ours = pd.read_excel('../RQ1/results/results_vmud.xlsx')
    fp_ours = {}
    tp_ours = {}
    fn_ours = {}
    for index, row in dataframe_ours.iterrows():
        row_dic = row.to_dict()
        if row['CVE-ID'] in thrown_cve:
            continue
        # if sigNum[row['CVE-ID']] in top_10:
        if sigNum[row['CVE-ID']] not in fp_ours.keys():
            fp_ours[sigNum[row['CVE-ID']]] = 0
            tp_ours[sigNum[row['CVE-ID']]] = 0
            fn_ours[sigNum[row['CVE-ID']]] = 0
        if row['result'] == "TP":
            tp_ours[sigNum[row['CVE-ID']]] += 1
        elif row_dic['result'] == "FP":
            fp_ours[sigNum[row['CVE-ID']]] += 1

    for repo in repos.keys():
        if repo not in fp_ours.keys():
            fp_ours[repo] = 0
            tp_ours[repo] = 0
            fn_ours[repo] = 0
        fn_ours[repo] = repoTP[repo] - tp_ours[repo]

    precision_ours = {}
    recall_ours = {}
    f1score_ours = {}
    for repo in repos.keys():
        if tp_ours[repo] == 0:
            precision_ours[repo] = 0
            recall_ours[repo] = 0
            f1score_ours[repo] = 0
        else:
            precision_ours[repo] = tp_ours[repo] / (tp_ours[repo] + fp_ours[repo])
            recall_ours[repo] = tp_ours[repo] / (tp_ours[repo] + fn_ours[repo])
            f1score_ours[repo] = (2 * precision_ours[repo] * recall_ours[repo]) / (precision_ours[repo] + recall_ours[repo])
    
    results_ours = {}
    for repo in repos.keys():
        results_ours[repo] = {}
        results_ours[repo]["TP"] = tp_ours[repo]
        results_ours[repo]["FP"] = fp_ours[repo]
        results_ours[repo]["FN"] = fn_ours[repo]
        results_ours[repo]["precision"] = precision_ours[repo]
        results_ours[repo]["recall"] = recall_ours[repo]
        results_ours[repo]["f1score"] = f1score_ours[repo]

    with open("./results/resultsCVE_vmud.json","w") as f:
        json.dump(results_ours, f)

def reformatCVE():
    f = open("./results/resultsCVE_vmud.json","r")
    resultsCVE_movery = json.load(f)
    f.close()
    tp = 0
    fp = 0
    fn = 0
    true_resultsCVE = {"10+":{"TP":0,"FP":0,"FN":0}}
    for cveNum in resultsCVE_movery.keys():
        if int(cveNum) > 10:
            true_resultsCVE["10+"]["TP"] += resultsCVE_movery[cveNum]["TP"]
            true_resultsCVE["10+"]["FP"] += resultsCVE_movery[cveNum]["FP"]
            true_resultsCVE["10+"]["FN"] += resultsCVE_movery[cveNum]["FN"]
        else:
            true_resultsCVE[cveNum] = resultsCVE_movery[cveNum]
            tp += true_resultsCVE[cveNum]["TP"]
            fp += true_resultsCVE[cveNum]["FP"]
            fn += true_resultsCVE[cveNum]["FN"]
    tp += true_resultsCVE["10+"]["TP"]
    fp += true_resultsCVE["10+"]["FP"]
    fn += true_resultsCVE["10+"]["FN"]
    print(tp,fp,fn)
    if true_resultsCVE["10+"]["TP"] == 0:
        true_resultsCVE["10+"]["precision"] = 0
        true_resultsCVE["10+"]["recall"] = 0
        true_resultsCVE["10+"]["f1score"] = 0
    else:
        true_resultsCVE["10+"]["precision"] = true_resultsCVE["10+"]["TP"] / (true_resultsCVE["10+"]["TP"] + true_resultsCVE["10+"]["FP"])
        true_resultsCVE["10+"]["recall"] = true_resultsCVE["10+"]["TP"] / (true_resultsCVE["10+"]["TP"] + true_resultsCVE["10+"]["FN"])
        true_resultsCVE["10+"]["f1score"] = 2*true_resultsCVE["10+"]["precision"]*true_resultsCVE["10+"]["recall"] / (true_resultsCVE["10+"]["precision"] + true_resultsCVE["10+"]["recall"])
    with open("./results/resultsCVE_vmud.json","w") as f:
        json.dump(true_resultsCVE,f)

if __name__ == "__main__":
    getcveResults()
    reformatCVE()
