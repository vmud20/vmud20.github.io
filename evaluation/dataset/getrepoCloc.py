import json
import os

def getFile():
    fileNum = {}
    codeNum = {}
    for repo in os.listdir("../data/cloc"):
        # if repo != "reading-code-of-nginx-1.9.2.txt":
        #     continue
        with open(os.path.join("../data/cloc", repo), "r") as f:
            lines = f.readlines()
            digits = []
            SUM_flag = False
            for line in lines:
                if line.strip().startswith("SUM"):
                    # print(line)
                    info = line.strip().split(" ")
                    i = 0
                    while i < len(info):
                        if info[i]=="":
                            i += 1
                            continue
                        if info[i].isdigit():
                            digits.append(int(info[i]))
                        i += 1

                    # print(line.split(" "))
                    SUM_flag = True
            if not SUM_flag:
                for line in lines:
                    if line.strip().startswith("C ") or line.strip().startswith("C++ "):
                        info = line.strip().split(" ")
                        i = 0
                        while i < len(info):
                            if info[i]=="":
                                i += 1
                                continue
                            if info[i].isdigit():
                                digits.append(int(info[i]))
                            i += 1

                        # print(line.split(" "))
                # print(repo)
            if digits == []:
                # print(repo)
                continue
            fileNum[repo.replace(".txt","")] = digits[0]
            codeNum[repo.replace(".txt","")] = digits[3]
            # print(fileNum,codeNum)
                # print(line)
            # break
    with open("repoFileNum.json","w") as f:
        json.dump(fileNum,f)
    with open("repoCodeNum.json","w") as f:
        json.dump(codeNum,f)


if __name__=="__main__":
    getFile()