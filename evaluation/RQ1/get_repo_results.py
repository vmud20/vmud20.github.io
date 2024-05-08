import pandas as pd
import ast
import json
import os
import pickle

f = open("thrown_cve.pkl","rb")
thrown_cve = pickle.load(f)
f.close()
fp = open("intersection_cve.pkl","rb")
our_cve = pickle.load(fp)
fp.close()

def getRepoResultsMovery():
    GTData = pd.read_csv("./results/GT.csv", encoding='utf-8')
    repos = {}
    repoNames = []
    for index, row in GTData.iterrows():
        if row['CVE-ID'] in thrown_cve:
            continue
        if row['CVE-ID'] not in our_cve:
            continue
        if row['repoName'] not in repos.keys():
            repos[row['repoName']] = []
        repos[row['repoName']].append(row.to_dict())
        
    repoTP = {}
    for index, row in GTData.iterrows(): 
        if row['CVE-ID'] in thrown_cve:
            continue
        if row['CVE-ID'] not in our_cve:
            continue
        if row['repoName'] not in repoTP.keys():
            repoTP[row['repoName']] = 0
        if row['result'] == "TP":
            repoTP[row['repoName']] += 1
    dataframe_movery = pd.read_csv('./results/results_movery.csv')
    fp_movery = {}
    tp_movery = {}
    fn_movery = {}
    for index, row in dataframe_movery.iterrows():
        row_dic = row.to_dict()
        if row['CVE-ID'] in thrown_cve:
            continue
        # if row['repoName'] in top_10:
        if row['repoName'] not in fp_movery.keys():
            fp_movery[row['repoName']] = 0
            tp_movery[row['repoName']] = 0
            fn_movery[row['repoName']] = 0
        if row['result'] == "TP":
            tp_movery[row['repoName']] += 1
        elif row_dic['result'] == "FP":
            fp_movery[row['repoName']] += 1

    for repo in repos.keys():
        if repo not in fp_movery.keys():
            fp_movery[repo] = 0
            tp_movery[repo] = 0
            fn_movery[repo] = 0
        fn_movery[repo] = repoTP[repo] - tp_movery[repo]
    precision_movery = {}
    recall_movery = {}
    f1score_movery = {}
    for repo in repos.keys():
        if tp_movery[repo] == 0:
            precision_movery[repo] = 0
            recall_movery[repo] = 0
            f1score_movery[repo] = 0
        else:
            precision_movery[repo] = tp_movery[repo] / (tp_movery[repo] + fp_movery[repo])
            recall_movery[repo] = tp_movery[repo] / (tp_movery[repo] + fn_movery[repo])
            f1score_movery[repo] = (2 * precision_movery[repo] * recall_movery[repo]) / (precision_movery[repo] + recall_movery[repo])
    results_movery = {}
    tp = 0
    fp = 0
    fn = 0
    for repo in repos.keys():
        results_movery[repo] = {}
        results_movery[repo]["TP"] = tp_movery[repo]
        results_movery[repo]["FP"] = fp_movery[repo]
        results_movery[repo]["FN"] = fn_movery[repo]
        results_movery[repo]["precision"] = precision_movery[repo]
        results_movery[repo]["recall"] = recall_movery[repo]
        results_movery[repo]["f1score"] = f1score_movery[repo]
        
        tp += results_movery[repo]["TP"]
        fp += results_movery[repo]["FP"]
        fn += results_movery[repo]["FN"]
    print(tp,fp,fn)
    with open("results_repo_movery.json","w") as f:
        json.dump(results_movery, f)

def getRepoResults():
    GTData = pd.read_csv("./results/GT.csv", encoding='utf-8')
    repos = {}
    repoNames = []
    for index, row in GTData.iterrows():
        if row['CVE-ID'] in thrown_cve:
            continue
        if row['repoName'] not in repos.keys():
            repos[row['repoName']] = []
        repos[row['repoName']].append(row.to_dict())
    
    repoTP = {}
    for index, row in GTData.iterrows(): 
        if row['CVE-ID'] in thrown_cve:
            continue
        if row['repoName'] not in repoTP.keys():
            repoTP[row['repoName']] = 0
        if row['result'] == "TP":
            repoTP[row['repoName']] += 1

    dataframe_ours = pd.read_excel('./results/results_vmud.xlsx')
    dataframe_MVP = pd.read_csv('./results/results_MVP.csv')
    dataframe_v1scan = pd.read_csv('./results/results_v1scan.csv', encoding='gbk')
    dataframe_vuddy = pd.read_excel('./results/results_vuddy.xlsx')
    fp_ours = {}
    tp_ours = {}
    fn_ours = {}
    for index, row in dataframe_ours.iterrows():
        row_dic = row.to_dict()
        if row['CVE-ID'] in thrown_cve:
            continue
        if row['repoName'] not in fp_ours.keys():
            fp_ours[row['repoName']] = 0
            tp_ours[row['repoName']] = 0
            fn_ours[row['repoName']] = 0
        if row['result'] == "TP":
            tp_ours[row['repoName']] += 1
        elif row_dic['result'] == "FP":
            fp_ours[row['repoName']] += 1

    for repo in repos.keys():
        if repo not in fp_ours.keys():
            fp_ours[repo] = 0
            tp_ours[repo] = 0
            fn_ours[repo] = 0
        fn_ours[repo] = repoTP[repo] - tp_ours[repo]

    


    fp_MVP = {}
    tp_MVP = {}
    fn_MVP = {}
    for index, row in dataframe_MVP.iterrows():
        row_dic = row.to_dict()
        if row['CVE-ID'] in thrown_cve:
            continue
        # if row['repoName'] in top_10:
        if row['repoName'] not in fp_MVP.keys():
            fp_MVP[row['repoName']] = 0
            tp_MVP[row['repoName']] = 0
            fn_MVP[row['repoName']] = 0
        if row['result'] == "TP":
            tp_MVP[row['repoName']] += 1
        elif row_dic['result'] == "FP":
            fp_MVP[row['repoName']] += 1

    for repo in repos.keys():
        if repo not in fp_MVP.keys():
            fp_MVP[repo] = 0
            tp_MVP[repo] = 0
            fn_MVP[repo] = 0
        fn_MVP[repo] = repoTP[repo] - tp_MVP[repo]


    fp_v1scan = {}
    tp_v1scan = {}
    fn_v1scan = {}
    for index, row in dataframe_v1scan.iterrows():
        row_dic = row.to_dict()
        if row['CVE-ID'] in thrown_cve:
            continue
        # if row['repoName'] in top_10:
        if row['repoName'] not in fp_v1scan.keys():
            fp_v1scan[row['repoName']] = 0
            tp_v1scan[row['repoName']] = 0
            fn_v1scan[row['repoName']] = 0
        if row['result'] == "TP":
            tp_v1scan[row['repoName']] += 1
        elif row_dic['result'] == "FP":
            fp_v1scan[row['repoName']] += 1

    for repo in repos.keys():
        if repo not in fp_v1scan.keys():
            fp_v1scan[repo] = 0
            tp_v1scan[repo] = 0
            fn_v1scan[repo] = 0
        fn_v1scan[repo] = repoTP[repo] - tp_v1scan[repo]

    fp_vuddy = {}
    tp_vuddy = {}
    fn_vuddy = {}
    for index, row in dataframe_vuddy.iterrows():
        row_dic = row.to_dict()
        if row['CVE-ID'] in thrown_cve:
            continue
        # if row['repoName'] in top_10:
        if row['repoName'] not in fp_vuddy.keys():
            fp_vuddy[row['repoName']] = 0
            tp_vuddy[row['repoName']] = 0
            fn_vuddy[row['repoName']] = 0
        if row['result'] == "TP":
            tp_vuddy[row['repoName']] += 1
        elif row_dic['result'] == "FP":
            fp_vuddy[row['repoName']] += 1

    for repo in repos.keys():
        if repo not in fp_vuddy.keys():
            fp_vuddy[repo] = 0
            tp_vuddy[repo] = 0
            fn_vuddy[repo] = 0
        fn_vuddy[repo] = repoTP[repo] - tp_vuddy[repo]


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

    

    precision_MVP = {}
    recall_MVP = {}
    f1score_MVP = {}
    for repo in repos.keys():
        if tp_MVP[repo] == 0:
            precision_MVP[repo] = 0
            recall_MVP[repo] = 0
            f1score_MVP[repo] = 0
        else:
            precision_MVP[repo] = tp_MVP[repo] / (tp_MVP[repo] + fp_MVP[repo])
            recall_MVP[repo] = tp_MVP[repo] / (tp_MVP[repo] + fn_MVP[repo])
            f1score_MVP[repo] = (2 * precision_MVP[repo] * recall_MVP[repo]) / (precision_MVP[repo] + recall_MVP[repo])


    precision_v1scan = {}
    recall_v1scan = {}
    f1score_v1scan = {}
    for repo in repos.keys():
        if tp_v1scan[repo] == 0:
            precision_v1scan[repo] = 0
            recall_v1scan[repo] = 0
            f1score_v1scan[repo] = 0
        else:
            precision_v1scan[repo] = tp_v1scan[repo] / (tp_v1scan[repo] + fp_v1scan[repo])
            recall_v1scan[repo] = tp_v1scan[repo] / (tp_v1scan[repo] + fn_v1scan[repo])
            f1score_v1scan[repo] = (2 * precision_v1scan[repo] * recall_v1scan[repo]) / (precision_v1scan[repo] + recall_v1scan[repo])


    precision_vuddy = {}
    recall_vuddy = {}
    f1score_vuddy = {}
    for repo in repos.keys():
        if tp_vuddy[repo] == 0:
            precision_vuddy[repo] = 0
            recall_vuddy[repo] = 0
            f1score_vuddy[repo] = 0
        else:
            precision_vuddy[repo] = tp_vuddy[repo] / (tp_vuddy[repo] + fp_vuddy[repo])
            recall_vuddy[repo] = tp_vuddy[repo] / (tp_vuddy[repo] + fn_vuddy[repo])
            f1score_vuddy[repo] = (2 * precision_vuddy[repo] * recall_vuddy[repo]) / (precision_vuddy[repo] + recall_vuddy[repo])

    results_vuddy = {}
    tp = 0
    fp = 0
    fn = 0
    for repo in repos.keys():
        results_vuddy[repo] = {}
        results_vuddy[repo]["TP"] = tp_vuddy[repo]
        results_vuddy[repo]["FP"] = fp_vuddy[repo]
        results_vuddy[repo]["FN"] = fn_vuddy[repo]
        results_vuddy[repo]["precision"] = precision_vuddy[repo]
        results_vuddy[repo]["recall"] = recall_vuddy[repo]
        results_vuddy[repo]["f1score"] = f1score_vuddy[repo]
        tp += results_vuddy[repo]["TP"]
        fp += results_vuddy[repo]["FP"]
        fn += results_vuddy[repo]["FN"]
    print(tp,fp,fn) 
    with open("results_repo_vuddy.json","w") as f:
        json.dump(results_vuddy, f)
    results_v1scan = {}
    tp = 0
    fp = 0
    fn = 0
    for repo in repos.keys():
        results_v1scan[repo] = {}
        results_v1scan[repo]["TP"] = tp_v1scan[repo]
        results_v1scan[repo]["FP"] = fp_v1scan[repo]
        results_v1scan[repo]["FN"] = fn_v1scan[repo]
        results_v1scan[repo]["precision"] = precision_v1scan[repo]
        results_v1scan[repo]["recall"] = recall_v1scan[repo]
        results_v1scan[repo]["f1score"] = f1score_v1scan[repo]

        tp += results_v1scan[repo]["TP"]
        fp += results_v1scan[repo]["FP"]
        fn += results_v1scan[repo]["FN"]
    print(tp,fp,fn) 
    with open("results_repo_v1scan.json","w") as f:
        json.dump(results_v1scan, f)

    results_MVP = {}
    tp = 0
    fp = 0
    fn = 0
    for repo in repos.keys():
        results_MVP[repo] = {}
        results_MVP[repo]["TP"] = tp_MVP[repo]
        results_MVP[repo]["FP"] = fp_MVP[repo]
        results_MVP[repo]["FN"] = fn_MVP[repo]
        results_MVP[repo]["precision"] = precision_MVP[repo]
        results_MVP[repo]["recall"] = recall_MVP[repo]
        results_MVP[repo]["f1score"] = f1score_MVP[repo]
        tp += results_MVP[repo]["TP"]
        fp += results_MVP[repo]["FP"]
        fn += results_MVP[repo]["FN"]
    with open("results_repo_MVP.json","w") as f:
        json.dump(results_MVP, f)
    print(tp,fp,fn)

    results_ours = {}
    tp = 0
    fp = 0
    fn = 0
    for repo in repos.keys():
        results_ours[repo] = {}
        results_ours[repo]["TP"] = tp_ours[repo]
        results_ours[repo]["FP"] = fp_ours[repo]
        results_ours[repo]["FN"] = fn_ours[repo]
        results_ours[repo]["precision"] = precision_ours[repo]
        results_ours[repo]["recall"] = recall_ours[repo]
        results_ours[repo]["f1score"] = f1score_ours[repo]
        tp += results_ours[repo]["TP"]
        fp += results_ours[repo]["FP"]
        fn += results_ours[repo]["FN"]
    print(tp,fp,fn)

    with open("results_repo_vmud.json","w") as f:
        json.dump(results_ours, f)

if __name__ == "__main__":
    getRepoResults()
    getRepoResultsMovery()
    