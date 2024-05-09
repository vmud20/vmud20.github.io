import json
import os
import hashlib
import re
import sys
import time
import copy
from queue import Queue
from xml.dom.minidom import parse
import subprocess
from datetime import datetime
from tqdm import tqdm
import pickle

encoding_format="ISO-8859-1"
file = open("./config.json")
info = json.load(file)
file.close()
work_dir = info["work_path"]
saga_dir = info["saga_path"]
signature_path = info["signature_path"]
signature_path_old = info["signature_path_old"]
progress_file=info["progress_file"]
saga_file = info["saga_multi"]
vulFileMulti = info["vulFileMulti"]
ctagsPath = info["ctagsPath"]
process_file = info["process_file"]
tempSignature = info["tempSignature"]
temp_work_dir = info["work_path"]
targetRepoMacros = info["targetRepoMacros"]
pagerank_location_prefix = info["pagerank_location_prefix"]
pagerank_threshold = info["pagerank_threshold"]
th_syn_v = info["th_syn_v"]
th_sem_v = info["th_sem_v"]
th_syn_p = info["th_syn_p"]
th_sem_p = info["th_sem_p"]
th_ce = info["th_ce"]
includeFiles = []
analysizedFiles = []
removedMacros = ["__FILE__", "__LINE__", "__DATE__", "__TIME__", "__STDC__", "__STDC_VERSION__", 
                "__cplusplus", "__GNUC__", "__GNUC_MINOR__", "__GNUC_PATCHLEVEL__", "__BASE_FILE__", "__FILE_NAME__", 
                "__INCLUDE_LEVEL__", "__VERSION__","__CHAR_UNSIGNED__", "__WCHAR_UNSIGNED__","__REGISTER_PREFIX__", "__USER_LABEL_PREFIX__"]


def format_and_del_comment_usegcc(src, repoName, fileName):
    with open(src, "r", encoding=encoding_format) as f:
        file_contents = f.readlines()
        i = 0
        while i < len(file_contents):
            file_pure_contents = file_contents[i].strip().replace(" ","")
            if file_pure_contents.startswith("#include") and "/" in file_pure_contents:
                file_contents[i] = "\n"
                continue
            if file_pure_contents.startswith("#if0"):
                j = i
                while j < len(file_contents):
                    file_pure_contents_in = file_contents[j].strip().replace(" ","")
                    if file_pure_contents_in.startswith("#else") or file_pure_contents_in.startswith("#endif"):
                        break
                    else:
                        file_contents[j] = "\n"
                    j += 1
                i = j  
            if file_pure_contents.startswith("#if") or file_pure_contents.startswith("#elif") or file_pure_contents.startswith("#else") or file_pure_contents.startswith("#ifdef") or file_pure_contents.startswith("#ifndef") or file_pure_contents.startswith("#endif"):
                if file_contents[i].strip().replace(" ","").endswith("\\"):
                    file_contents[i] = "\n"
                    j = i + 1  
                    while j < len(file_contents):
                        if file_contents[j].strip().replace(" ","").endswith("\\"):
                            file_contents[j] = "\n"
                        else:
                            file_contents[j] = "\n"
                            break
                        j += 1
                    i = j
                else:
                    file_contents[i] = "\n"

            for macro in removedMacros:
                file_contents[i] = file_contents[i].replace(macro, "\"{0}\"".format(macro))
            if file_contents[i].lstrip().replace(" ","").startswith("#error"):
                file_contents[i] = "\n"
            if file_contents[i].strip().startswith("#define") and len(file_contents[i].strip().replace("\t"," ").split(" ")) <= 2 and not file_contents[i].strip().endswith("\\"):
                file_contents[i] = "\n"
            i += 1
        with open(src, "w", encoding=encoding_format) as fp:
            fp.write("".join(file_contents))
    cmd = "gcc -E -w -include \"" + targetRepoMacros + "/{0}/macro_{1}.h\" \"{2}\" -o \"{3}\"".format(repoName, fileName, src, src.replace(".c", "_gcc.c"))
    relines = []
    with open(targetRepoMacros + "/{0}/macro_{1}.h".format(repoName, fileName), "r") as f:
        lines = f.readlines()
        i = 0
        while i < len(lines):
            if lines[i].strip().startswith("#define") and not lines[i].strip().replace(" ","").endswith("\\") and len(lines[i].lstrip().replace("\t"," ").split(" ")) <= 2:
                lines[i] = "\n"
            relines.append(lines[i])
            i += 1
    with open(targetRepoMacros+ "/{0}/macro_{1}.h".format(repoName, fileName), "w") as f:
        f.writelines(relines)
    gcc_finish = False
    preMsg = ""
    first_try = False
    pure_fileName = fileName
    while not gcc_finish:
        try:
            cmd = "gcc -E -w -include \"" + targetRepoMacros + "/{0}/macro_{1}.h\" \"{2}\" -o \"{3}\"".format(repoName, pure_fileName, src, src.replace(".c", "_gcc.c"))
            subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True).decode(errors='replace')
            gcc_finish = True
        except subprocess.CalledProcessError as e:
            err_msg = e.output.decode()
            if preMsg == err_msg:
                if first_try:
                    format_and_del_comment(src)
                    return
                else:
                    with open(f"{targetRepoMacros}{repoName}/macro_{pure_fileName}.h", "r", encoding=encoding_format) as f:
                        file_contents = f.readlines()
                        i = 0
                        while i < len(file_contents):
                            if file_contents[i].strip().replace(" ","").startswith("#include"):
                                file_contents[i] = "\n"
                            i += 1
                        fp = open(f"{targetRepoMacros}{repoName}/macro_{pure_fileName}.h", "w")
                        fp.writelines(file_contents)
                    with open(src, "r", encoding=encoding_format) as f:
                        file_contents = f.readlines()
                        i = 0
                        while i < len(file_contents):
                            if file_contents[i].strip().replace(" ","").startswith("#include"):
                                file_contents[i] = "\n"
                            i += 1
                        fp = open(src, "w")
                        fp.writelines(file_contents)
                    first_try = True
            else:
                preMsg = err_msg
            msgs = err_msg.split("\n")
            i = 0
            while i < len(msgs):
                msg = msgs[i]
                pattern1 = r'requires (\d+) arguments, but only (\d+) given'
                pattern2 = r'fatal error: ([^:]+): No such file or directory'
                pattern3 = r'passed (\d+) arguments, but takes just (\d+)'
                pattern4 = r'error: missing binary operator before token "\("'
                pattern5 = r'error: #endif without #if'
                pattern6 = r'error: #else without #if'
                pattern7 = r'error: ' 
                match = re.search(pattern1, msg)
                match2 = re.search(pattern2, msg)
                match3 = re.search(pattern3, msg)
                match4 = re.search(pattern4, msg)
                match5 = re.search(pattern5, msg)
                match6 = re.search(pattern6, msg)
                match7 = re.search(pattern7, msg)
                if match:
                    info = msgs[i+4]
                    fileName = info.split(":")[0].strip()
                    if not (targetRepoMacros not in fileName or pure_fileName not in fileName):
                        i += 1
                        continue
                    lineNumber = info.split(":")[1].strip()
                    f = open(fileName, 'r', encoding='utf-8', errors='replace')
                    lines = f.readlines()
                    lines[int(lineNumber)-1] = "\n"
                    f.close()
                    fp = open(fileName, 'w', encoding='utf-8', errors='replace')
                    fp.writelines(lines)
                    fp.close()
                    i += 6
                elif match2:
                    info = msg
                    fileName = info.split(":")[0].strip()
                    if not (targetRepoMacros not in fileName or pure_fileName not in fileName):
                        i += 1
                        continue
                    lineNumber = info.split(":")[1].strip()
                    f = open(fileName, 'r', encoding='utf-8', errors='replace')
                    lines = f.readlines()
                    lines[int(lineNumber)-1] = "\n"
                    f.close()
                    fp = open(fileName, 'w', encoding='utf-8', errors='replace')
                    fp.writelines(lines)
                    fp.close()
                    i+=1
                elif match3:                   
                    if len(msgs[i+4].split(":")) > 1:
                        info = msgs[i+4]
                        i += 6
                    else:
                        info = msg
                        i += 1
                    fileName = info.split(":")[0].strip()
                    if not (targetRepoMacros not in fileName or pure_fileName not in fileName):
                        i += 1
                        continue
                    lineNumber = info.split(":")[1].strip()
                    f = open(fileName, 'r', encoding='utf-8', errors='replace')
                    lines = f.readlines()
                    lines[int(lineNumber)-1] = "\n"
                    f.close()
                    fp = open(fileName, 'w', encoding='utf-8', errors='replace')
                    fp.writelines(lines)
                    fp.close()
                elif match4 or match5 or match6 or match7:
                    info = msg
                    fileName = info.split(":")[0].strip()
                    if not (targetRepoMacros not in fileName or pure_fileName not in fileName):
                        i += 1
                        continue
                    lineNumber = info.split(":")[1].strip()
                    f = open(fileName, 'r', encoding='utf-8', errors='replace')
                    lines = f.readlines()
                    lines[int(lineNumber)-1] = "\n"
                    f.close()
                    fp = open(fileName, 'w', encoding='utf-8', errors='replace')
                    fp.writelines(lines)
                    fp.close()
                    i+=1
                else:
                    i += 1
    with open(src.replace(".c", "_gcc.c"), "r", encoding=encoding_format) as f:
        lines = f.readlines()
        i = 0
        while i < len(lines):
            if lines[i].endswith("\\\n"):
                temp = i
                while lines[i].endswith("\\\n"):
                    i += 1
                lines[temp] = lines[temp][:-2]
                for k in range(temp + 1, i + 1):
                    if k == len(lines):
                        break
                    lines[temp] += " "
                    lines[temp] += lines[k][:-2].strip()
                    lines[k] = "\n"
            else:
                i += 1
    with open(src, "w", encoding=encoding_format) as f:
        f.writelines(lines)
    with open(src, "r", encoding=encoding_format) as f:
        lines = f.readlines()
        i = 0
        while i < len(lines):
            if lines[i].startswith("# "):
                while src not in lines[i]:
                    lines[i] = "\n"
                    i += 1
                lines[i] = "\n"
            i += 1
    with open(src, "w", encoding=encoding_format) as f:
        f.writelines(lines)
    with open(src, "r", encoding=encoding_format) as f:
        lines = f.readlines()
        i = 0
        preTemp = 0
        while i < len(lines):
            if (
                lines[i].strip() == "\n"
                or lines[i].strip() == "\r\n"
                or lines[i].strip() == ""
            ):
                i += 1
            elif lines[i].strip() == ";":
                if lines[preTemp].strip().endswith("{"):
                    lines[preTemp] = lines[preTemp][:-2] + ";\n"
                    lines[i] = "\n"
                    j = i
                    while j < len(lines) and not lines[j].strip()=="}":
                        j += 1
                    lines[j] = "\n"
                    i = j+1
                else:
                    lines[preTemp] = lines[preTemp].strip() + ";\n"
                    lines[i] = "\n"
            elif lines[i].strip().startswith("||") or lines[i].strip().startswith("&&") or lines[i].strip().startswith(")") or (lines[i].strip().startswith("(") and not lines[preTemp].strip().endswith("{") and not (lines[preTemp].strip().endswith(";") and not lines[preTemp].strip().startswith("for"))):
                lines[preTemp] = lines[preTemp].strip() + lines[i].lstrip()
                lines[i] = "\n"
                i = preTemp
            elif lines[i].lstrip().startswith("else") and lines[preTemp].strip().replace(" ","") == "}":
                lines[preTemp] = lines[preTemp].strip() + lines[i].lstrip()
                lines[i] = "\n"
                i = preTemp
            else:
                temp = i
                preTemp = i
                while (
                    i < len(lines)
                    and not lines[i].strip().endswith(";")
                    and not lines[i].strip().endswith("{")
                    and not (lines[i].strip().endswith(")") and (lines[i].strip().startswith("if") or lines[temp].strip().startswith("if")))
                    and not lines[i].strip().endswith("}")
                    and not lines[i].strip().startswith("#")
                ):
                    i += 1
                if temp != i:
                    lines[temp] = lines[temp][:-1]
                for j in range(temp + 1, i + 1):
                    if j == len(lines):
                        break
                    lines[temp] += " "
                    lines[temp] += lines[j][:-1].strip()
                    lines[j] = "\n"
                if temp == i:
                    i += 1
        i = 0
        while i < len(lines):
            lines[i] = lines[i].replace("_U_", "") 
            lines[i] = lines[i].replace("IN ", "")
            lines[i] = lines[i].replace("EFIAPI", "") 
            lines[i] = lines[i].replace("UNUSED_PARAM", "") 
            lines[i] = lines[i].replace("NULL", "((void *)0)") 
            lines[i] = lines[i].replace("(((void *)0))", "((void *)0)") 
            lines[i] = lines[i].replace("false", "0").replace("true", "1")
            lines[i] = lines[i].replace("__declspec(dllexport) mrb_value","")
            lines[i] = lines[i].replace("extern \"C\"","")
            lines[i] = lines[i].replace("!!","")  
            if src in lines[i]:
                j = lines[i].replace(" ","").find(src)
                if lines[i].replace(" ","")[j + len(src)+1]=="," and lines[i].replace(" ","")[j + len(src)+2].isdigit():
                    k = lines[i].replace(" ","")[j + len(src)+2:].find(",")
                    if k != -1:
                        digit = lines[i].replace(" ","")[j + len(src)+2:j + len(src)+2+k]
                    else:
                        k = lines[i].replace(" ","")[j + len(src)+2:].find(")")
                        digit = lines[i].replace(" ","")[j + len(src)+2:j + len(src)+2+k]
                    lines[i] = lines[i].replace(src + ",","").replace(digit + ",", "").replace(src,"").replace(digit,"")

            if "&(*" in lines[i] or "*(&" in lines[i]:
                k = lines[i].find("&(*")
                if k == -1:
                    k = lines[i].find("*(&")
                if k == -1:
                    i += 1
                    continue
                bracket_count = 1
                for j in range(k + 3, len(lines[i])):
                    if lines[i][j] == "(":
                        bracket_count += 1
                    elif lines[i][j] == ")":
                        if bracket_count == 1:
                            lines[i] = lines[i][0:j] + lines[i][j+1:]
                            break
                        bracket_count -= 1
                lines[i] = lines[i].replace("&(*","").replace("*(&","")
            i += 1
    with open(src, "w", encoding=encoding_format) as f:
        f.writelines(lines)


def removeComment(string):
	# Code for removing C/C++ style comments. (Imported from VUDDY and ReDeBug.)
	# ref: https://github.com/squizz617/vuddy
	c_regex = re.compile(
		r'(?P<comment>//.*?$|[{}]+)|(?P<multilinecomment>/\*.*?\*/)|(?P<noncomment>\'(\\.|[^\\\'])*\'|"(\\.|[^\\"])*"|.[^/\'"]*)',
		re.DOTALL | re.MULTILINE)
	return ''.join([c.group('noncomment') for c in c_regex.finditer(string) if c.group('noncomment')])


def getsMacros(repoPath, repoName, fileName):	
	fileCnt  = 0
	lineCnt  = 0
	allMacs  = {}
	includes = set()
	macrosDict   = {}
	if os.path.exists(targetRepoMacros + repoName + '/macro_' + fileName + '.h'):
		return 
	if not os.path.isdir(targetRepoMacros + repoName):
		os.mkdir(targetRepoMacros + repoName)
	while includeFiles:
		analysisFile, prefix, level = includeFiles.pop()
		flag = False
		for path, dir, files in os.walk(repoPath):
			if prefix not in path:
				continue
			else:
				prefix = path
				flag = True
				break
		if flag:
			getInclude = False
			while not getInclude and prefix != "/".join(repoPath.split("/")[:-1]):
				if "extract.h" in analysisFile:
					analysisFile = analysisFile.split("\t")[0]
				filePath = os.path.join(prefix, analysisFile)
				if not os.path.isfile(filePath):
					filePath = os.path.join(prefix, "deps/lua/src", analysisFile)
					if not os.path.isfile(filePath):
						filePath = os.path.join(prefix,"include", analysisFile)
						if not os.path.isfile(filePath):
							prefix = "/".join(prefix.split("/")[:-1])
							continue
				if filePath in analysizedFiles:
					break
				else:
					analysizedFiles.append(filePath)
				getIncludeFiles(filePath, prefix, level + 1)
				try:
					functionList 	= subprocess.check_output(ctagsPath + ' -f - --kinds-C=* --fields=neKSt "' + filePath + '"', stderr=subprocess.STDOUT, shell=True).decode(errors='replace')
					f = open(filePath, 'r', encoding = "UTF-8", errors='replace')
					lines 		= f.readlines()
					allFuncs 	= str(functionList).split('\n')
					macro	   = re.compile(r'(macro)')
					number 		= re.compile(r'(\d+)')
					tmpString	= ""
					lineCnt 	+= len(lines)
					fileCnt 	+= 1
					macros	  = ""
					for i in allFuncs:
						elemList	= re.sub(r'[\t\s ]{2,}', '', i)
						elemList 	= elemList.split('\t')
						
						if i != '' and len(elemList) >= 6 and (macro.fullmatch(elemList[3]) or macro.fullmatch(elemList[4])):
							if macro.fullmatch(elemList[4]):
								macrosName = elemList[0]
								strStartLine 	 = int(number.search(elemList[5]).group(0))
								strEndLine 		 = int(number.search(elemList[6]).group(0))
							else:
								strStartLine 	 = int(number.search(elemList[4]).group(0))
								macrosName = elemList[0]
								if len(elemList) == 6:
									strEndLine 		 = int(number.search(elemList[5]).group(0))
								elif len(elemList) == 7:
									strEndLine 		 = int(number.search(elemList[6]).group(0))
							tmpString	= ""
							tmpString	= tmpString.join(lines[strStartLine - 1 : strEndLine])
							rawBody	 = tmpString
							macros 		+= rawBody
							if filePath.replace('/', '@@') not in allMacs:
								allMacs[filePath.replace('/', '@@')] = []
							if macrosName not in macrosDict.keys():
								allMacs[filePath.replace('/', '@@')].append(rawBody)
								macrosDict[macrosName] = level
							elif macrosDict[macrosName] > level:
								allMacs[filePath.replace('/', '@@')].append(rawBody)
								macrosDict[macrosName] = level
				except subprocess.CalledProcessError as e:
					print("Parser Error:")
					print(e)
					continue
				except Exception as e:
					print("Subprocess failed")
					print(e)
					continue
				getInclude = True
				break
			if not getInclude:
				includes.add(analysisFile)

	f = open(targetRepoMacros + repoName + '/macro_' + fileName + '.h', 'w', encoding = "UTF-8")
	for include in includes:
		f.write("#include<{0}>\n".format(include))
	for fp in allMacs:
		for eachVal in allMacs[fp]:
			val = eachVal
			for macro in removedMacros:
				val = val.replace(macro, "\"{0}\"".format(macro))
			if "/* nothing */" in val:
				continue
			val = removeComment(val)
			if val.strip().startswith("#define") and len(val.strip().replace("\t"," ").split(" ")) <= 2 and not val.strip().endswith("\\"):
				continue
			f.write(val)
	f.close()


def getIncludeFiles(fileName, prefix, level):
	with open(fileName, "r", encoding=encoding_format) as f:
		lines = f.readlines()
		for line in lines:
			if line.lstrip().startswith("#include"):
				file = line.replace("#include","").replace("\"","").replace("<","").replace(">"," ").strip().split(" ")[0]
				includeFiles.append((file, prefix, level))



def parse(file_location, i):
    CONST_DICT = {"FP": "FPARAM", "LV": "LVAR", "DT": "DTYPE", "FC": "FUNCCALL"}
    FP_coor_list = []
    LV_coor_list = []
    DT_coor_list = []
    FC_coor_list = []
    with open("normalizeJson/FP" + i.__str__() + ".json", "r", encoding="utf8") as f:
        FP_coor_list = json.load(f)
    with open("normalizeJson/newLV" + i.__str__() + ".json", "r", encoding="utf8") as f:
        LV_coor_list = json.load(f)
    with open("normalizeJson/DT" + i.__str__() + ".json", "r", encoding="utf8") as f:
        DT_coor_list = json.load(f)
    with open("normalizeJson/FC" + i.__str__() + ".json", "r", encoding="utf8") as f:
        FC_coor_list = json.load(f)
    with open("normalizeJson/STRING" + i.__str__() + ".json", "r", encoding="utf8") as f:
        STRING_coor_list = json.load(f)
    change_dict = {}
    for FP in FP_coor_list:
        if FP["_2"] not in change_dict.keys():
            change_dict[FP["_2"]] = {}
        change_dict[FP["_2"]][FP["_3"]] = {}
        change_dict[FP["_2"]][FP["_3"]]["type"] = "FP"
        change_dict[FP["_2"]][FP["_3"]]["code"] = FP["_1"]
    for LV in LV_coor_list:
        if LV["_1"] == "NULL":
            continue
        if LV["_2"] not in change_dict.keys():
            change_dict[LV["_2"]] = {}
        change_dict[LV["_2"]][LV["_3"]] = {}
        change_dict[LV["_2"]][LV["_3"]]["type"] = "LV"
        change_dict[LV["_2"]][LV["_3"]]["code"] = LV["_1"]
    for DT in DT_coor_list:
        if "*" in DT["_1"] and "[" in DT["_1"]:
            continue
        if DT["_4"] not in change_dict.keys():
            change_dict[DT["_4"]] = {}
        code = DT["_1"]
        typeFullName = DT["_3"]
        DT_dup = False
        for col in change_dict[DT["_4"]].keys():
            if change_dict[DT["_4"]][col]["type"] == "DT":
                if change_dict[DT["_4"]][col]["typeFullName"] == typeFullName:
                    DT_dup = True
                    break
        if DT_dup:
            continue
        pointer_cnt = 0
        for char in code:
            if char == '*':
                pointer_cnt += 1
        if pointer_cnt != 0:
            delete_col = []
            for col in change_dict[DT["_4"]].keys():
                if change_dict[DT["_4"]][col]["type"] == "LV":
                    delete_col.append(col)
            for col in delete_col:
                change_dict[DT["_4"]][col + 1] = change_dict[DT["_4"]][col]
                change_dict[DT["_4"]].pop(col)
        name = DT["_2"]
        pos = DT["_5"]
        if pointer_cnt != 0:
            pos += 1
        index = code.rfind(name)
        index = pos - index
        change_dict[DT["_4"]][index] = {}
        change_dict[DT["_4"]][index]["pos"] = pos
        change_dict[DT["_4"]][index]["type"] = "DT"
        change_dict[DT["_4"]][index]["code"] = DT["_1"]
        change_dict[DT["_4"]][index]["name"] = DT["_2"]
        change_dict[DT["_4"]][index]["typeFullName"] = DT["_3"]
        change_dict[DT["_4"]][index]["pointerCnt"] = pointer_cnt
    for FC in FC_coor_list:
        if FC["_2"] not in change_dict.keys():
            change_dict[FC["_2"]] = {}
        change_dict[FC["_2"]][FC["_3"]] = {}
        change_dict[FC["_2"]][FC["_3"]]["type"] = "FC"
        change_dict[FC["_2"]][FC["_3"]]["code"] = FC["_1"]
    for STRING in STRING_coor_list:
        if STRING["_2"] not in change_dict.keys():
            change_dict[STRING["_2"]] = {}
        change_dict[STRING["_2"]][STRING["_3"]] = {}
        change_dict[STRING["_2"]][STRING["_3"]]["type"] = "STRING"
        change_dict[STRING["_2"]][STRING["_3"]]["code"] = STRING["_1"]
        fmt_pattern = r"%[\\.]*[0-9]*[.\-*#]*[0-9]*[hljztL]*[diuoxXfFeEgGaAcCsSpnm]"
        fmt_list = re.findall(fmt_pattern, STRING["_1"][1:-1])
        if len(fmt_list) != 0:
            write_code = ''.join(fmt_list)
            write_code = '"' + write_code + '"'
            change_dict[STRING["_2"]][STRING["_3"]]["write"] = write_code
        else:
            change_dict[STRING["_2"]][STRING["_3"]]["write"] = "STRING"
    with open(file_location, "r", encoding=encoding_format) as f:
        fp = f.readlines()
        for line_number in change_dict:
            change_dict[line_number] = sorted(change_dict[line_number].items())
            line = fp[line_number - 1]
            write_line = ""
            length = len(change_dict[line_number])
            for i in range(length):
                column_number = change_dict[line_number][i][0]
                if i != length - 1:
                    column_number_next = change_dict[line_number][i + 1][0]
                element_dict = change_dict[line_number][i][1]
                change_type = element_dict["type"]
                if i == 0:
                    if change_type != "DT":
                        write_line += line[:column_number - 1]
                        if change_type != "STRING":
                            write_line += CONST_DICT[change_type]
                        else:
                            write_line += element_dict["write"]
                        if i != length - 1:
                            write_line += line[column_number - 1 + len(element_dict["code"]):column_number_next - 1]
                        else:
                            write_line += line[column_number - 1 + len(element_dict["code"]):]
                    else:
                        write_line += line[:column_number - 1]
                        write_line += CONST_DICT[change_type]
                        if i != length - 1:
                            write_line += line[
                                          element_dict["pos"] - 2 - element_dict["pointerCnt"]:column_number_next - 1]
                        else:
                            write_line += line[column_number - 1 + len(element_dict["name"]):]
                elif i == length - 1:
                    if change_type != "DT":
                        if change_type != "STRING":
                            write_line += CONST_DICT[change_type]
                        else:
                            write_line += element_dict["write"]
                        write_line += line[column_number - 1 + len(element_dict["code"]):]
                    else:
                        write_line += CONST_DICT[change_type]
                        write_line += line[column_number - 1 + len(element_dict["name"]):]
                else:
                    if change_type != "DT":
                        if change_type != "STRING":
                            write_line += CONST_DICT[change_type]
                        else:
                            write_line += element_dict["write"]
                        if i != length - 1:
                            write_line += line[column_number - 1 + len(element_dict["code"]):column_number_next - 1]
                        else:
                            write_line += line[column_number - 1 + len(element_dict["code"]):]
                    else:
                        write_line += CONST_DICT[change_type]
                        if i != length - 1:
                            write_line += line[column_number - 1 + len(element_dict["name"]):column_number_next - 1]
                        else:
                            write_line += line[column_number - 1 + len(element_dict["name"]):]

            if write_line[-1] != "\n":
                write_line += "\n"
            fp[line_number - 1] = write_line
    with open(file_location, "w", encoding=encoding_format) as f:
        f.writelines(fp)


def jsonify(i):
    with open("normalizeJson/LV" + i.__str__() + ".json", "r", encoding="utf8") as f:
        fp = f.readlines()
        lines = []
        for fpline in fp:
            if "Some" not in fpline:
                continue
            index_some = fpline.find("Some")
            if "Some" not in fpline[index_some + 3:]:
                continue
            index_some2 = fpline[index_some + 3:].find("Some")
            dict = {}
            dict["_1"] = fpline[1:index_some - 1]
            dict["_2"] = int(fpline[index_some + 5:index_some + 3 + index_some2 - 2])
            if fpline[-1] == "\n":
                dict["_3"] = int(fpline[index_some + 4 + index_some2 + 4:-3])
            else:
                dict["_3"] = int(fpline[index_some + 4 + index_some2 + 4:-2])
            lines.append(dict)
    with open("normalizeJson/newLV" + i.__str__() + ".json", "w", encoding="utf8") as f:
        f.writelines(json.dumps(lines))


def format_and_del_comment(src):
    with open(src, 'r', encoding=encoding_format) as f:
        file_contents = f.read()
    c_regex = re.compile(
        r'(?P<comment>//.*?$|[{}]+)|(?P<multilinecomment>/\*.*?\*/)|(?P<noncomment>\'(\\.|[^\\\'])*\'|"(\\.|[^\\"])*"|.[^/\'"]*)',
        re.DOTALL | re.MULTILINE)
    with open(src,'w',encoding=encoding_format) as f:
        f.write(''.join([c.group('noncomment') for c in c_regex.finditer(file_contents) if c.group('noncomment')]))
    with open(src, "r", encoding=encoding_format) as f:
        lines = f.readlines()
        i = 0
        while i < len(lines):
            if lines[i].endswith("\\\n"):
                temp = i
                while lines[i].endswith("\\\n"):
                    i += 1
                lines[temp] = lines[temp][:-2]
                for k in range(temp + 1, i + 1):
                    if k == len(lines):
                        break
                    lines[temp] += " "
                    lines[temp] += lines[k][:-2].strip()
                    lines[k] = "\n"
            else:
                i += 1
    with open(src, "w", encoding=encoding_format) as f:
        f.writelines(lines)
    with open(src, "r", encoding=encoding_format) as f:
        lines = f.readlines()
        for i in range(len(lines)):
            if lines[i].startswith("#"):
                lines[i] = "\n"
    with open(src, "w", encoding=encoding_format) as f:
        f.writelines(lines)
    with open(src, "r", encoding=encoding_format) as f:
        lines = f.readlines()
        i = 0
        while i < len(lines):
            if lines[i].strip() == "\n" or lines[i].strip() == "\r\n" or lines[i].strip() == "":
                i += 1
            else:
                temp = i
                while i < len(lines) and not lines[i].strip().endswith(";") and not lines[i].strip().endswith("{") and not lines[i].strip().endswith(
                        ")") and not \
                        lines[i].strip().endswith("}") and not lines[i].strip().endswith(":") and not lines[i].strip().startswith("#"):
                    i += 1
                if temp != i:
                    lines[temp] = lines[temp][:-1]
                for j in range(temp + 1, i + 1):
                    if j == len(lines):
                        break
                    lines[temp] += " "
                    lines[temp] += lines[j][:-1].strip()
                    lines[j] = "\n"
                if temp == i:
                    i += 1
    with open(src, "w", encoding=encoding_format) as f:
        f.writelines(lines)

def detect_get_method_list(detect_dir, detect_file, method_list, gcc):
    file_name = detect_file.split("/")[-1]
    if gcc:
        analysizedFiles.clear()
        includeFiles.append(("", detect_file, 0))
        prefix = "/".join(detect_file.split("/")[:-1])
        getIncludeFiles(detect_file, prefix, 1)
        getsMacros(detect_dir,detect_dir.split("/")[-1],detect_file.replace("/","_"))
    try:
        os.system("cp \"" + detect_file + "\" \""+ temp_work_dir+ "temp/" + file_name+"\"")
        if gcc:
            format_and_del_comment_usegcc(temp_work_dir + "temp/" + file_name, detect_dir.split("/")[-1],detect_file.replace("/","_"))
        else:
            format_and_del_comment(temp_work_dir + "temp/" + file_name)
        os.system("./joern-parse \"" + temp_work_dir + "temp/" + file_name+"\"")
        os.system("./joern --script metadata.sc --params cpgFile=cpg.bin")
        with open("./method.json", "r") as f:
            json_obj = json.load(f)
            for obj in json_obj:
                if "lineNumber" in obj.keys() and obj["fullName"] != ":<global>" and "signature" in obj.keys() and obj["signature"] != "":
                    method_list.append([obj["code"], obj["lineNumber"], obj["lineNumberEnd"]])
        os.system("cp \"" + temp_work_dir + "temp/" + file_name + "\" " + temp_work_dir + "\"normalized/" + file_name+"\"")
        method_list_json = []
        for method_info in method_list:
            method_list_json.append({"signature": method_info[0], "lineNumber": method_info[1], "lineNumberEnd": method_info[2]})
        with open("./method_filtered.json", "w", encoding="utf8") as f:
            json.dump(method_list_json, f)
        return method_list
    except Exception as e:
        print(str(e))
        print("Error when detecting file:" + detect_file)

def detect_normalize1(file_name, i):
    jsonify(i)
    parse(temp_work_dir + "normalized/" + file_name, i)

def detect_slicing1(i):
    label_line_map = {}
    cdg_map = {}
    ddg_map = {}
    with open("slicingJson/PDG" + i.__str__() + ".json", "r", encoding="utf8") as f:
        json_object = json.load(f)
        if len(json_object) == 0:
            return cdg_map, ddg_map
        list1 = json_object[0].split("\n")
        for line in list1:
            if not line.startswith("digraph"):
                if line.startswith('"'):
                    num_end = line.find('"', 1)
                    label_number = int(line[1:num_end])
                    line_number_start = line.find("<SUB>")
                    line_number_end = line.find("</SUB>")
                    if line_number_start == -1 or line_number_end == -1:
                        continue
                    line_number = int(line[line_number_start + 5:line_number_end])
                    label_line_map[label_number] = line_number
                elif len(line) > 1:
                    from_end = line.find('"', 3)
                    from_label = int(line[3:from_end])
                    to_start = line.find('"', from_end + 1)
                    to_end = line.find('"', to_start + 1)
                    to_label = int(line[to_start + 1:to_end])
                    label_start = line.find('[ label = "')
                    label = line[label_start + 11:-3]
                    if from_label not in label_line_map.keys() or to_label not in label_line_map.keys():
                        continue
                    if label_line_map[from_label] != label_line_map[to_label]:
                        if label.startswith("CDG"):
                            if label_line_map[from_label] not in cdg_map.keys():
                                cdg_map[label_line_map[from_label]] = set()
                            cdg_map[label_line_map[from_label]].add(label_line_map[to_label])
                        else:
                            if label_line_map[from_label] not in ddg_map.keys():
                                ddg_map[label_line_map[from_label]] = set()
                            ddg_map[label_line_map[from_label]].add(label_line_map[to_label])
    return cdg_map, ddg_map


def detect_generate_signature(file_name, method_info, cdg_map, ddg_map,work_dir, gcc):
    func_syn = {}
    func_sem = {}
    func_merge = {}
    with open(temp_work_dir + "normalized/" + file_name, "r",encoding=encoding_format) as f:
        lines = f.readlines()
        for i in range(method_info[1] + 1, method_info[2] + 1):
            if gcc:
                temp_str = lines[i - 1].replace(" ", "").replace("{", "").replace("}", "").replace("\t", "").replace("\n", "").replace("(", "").replace(")", "")
            else:
                temp_str = lines[i - 1].replace(" ", "").replace("{", "").replace("}", "").replace("\t", "").replace("\n", "")
            if temp_str != "":
                m = hashlib.md5()
                m.update(temp_str.encode(encoding_format))
                func_syn[str(i)] = m.hexdigest()[:6]
        for key in cdg_map.keys():
            if not method_info[1] + 1 <= key <= method_info[2]:
                continue
            for line in cdg_map[key]:
                if method_info[1] + 1 <= line <= method_info[2]:
                    if gcc:
                        temp_str1 = lines[key - 1].replace(" ", "").replace("{", "").replace("}", "").replace("\t", "").replace("\n", "").replace("(", "").replace(")", "")
                        temp_str2 = lines[line - 1].replace(" ", "").replace("{", "").replace("}", "").replace("\t", "").replace("\n", "").replace("(", "").replace(")", "")
                    else:
                        temp_str1 = lines[key - 1].replace(" ", "").replace("{", "").replace("}", "").replace("\t", "").replace("\n", "")
                        temp_str2 = lines[line - 1].replace(" ", "").replace("{", "").replace("}", "").replace("\t", "").replace("\n", "")
                    if temp_str1 != "" and temp_str2 != "":
                        tuple1 = []
                        m = hashlib.md5()
                        m.update(temp_str1.encode(encoding_format))
                        tuple1.append(m.hexdigest()[:6])
                        m = hashlib.md5()
                        m.update(temp_str2.encode(encoding_format))
                        tuple1.append(m.hexdigest()[:6])
                        tuple1.append("control")
                        line_tuple_str = str(key) + "__split__" + str(line) + "__split__control"
                        func_sem[line_tuple_str] = tuple1
                        if str(key) not in func_merge.keys():
                            func_merge[str(key)] = []
                        if str(line) not in func_merge.keys():
                            func_merge[str(line)] = []
                        func_merge[str(key)].append(tuple1)
                        func_merge[str(line)].append(tuple1)
        for key in ddg_map.keys():
            if not method_info[1] + 1 <= key <= method_info[2]:
                continue
            for line in ddg_map[key]:
                if method_info[1] + 1 <= line <= method_info[2]:
                    if gcc:
                        temp_str1 = lines[key - 1].replace(" ", "").replace("{", "").replace("}", "").replace("\t", "").replace("\n", "").replace("(", "").replace(")", "")
                        temp_str2 = lines[line - 1].replace(" ", "").replace("{", "").replace("}", "").replace("\t", "").replace("\n", "").replace("(", "").replace(")", "")
                    else:
                        temp_str1 = lines[key - 1].replace(" ", "").replace("{", "").replace("}", "").replace("\t", "").replace("\n", "")
                        temp_str2 = lines[line - 1].replace(" ", "").replace("{", "").replace("}", "").replace("\t", "").replace("\n", "")
                    if temp_str1 != "" and temp_str2 != "":
                        tuple1 = []
                        m = hashlib.md5()
                        m.update(temp_str1.encode(encoding_format))
                        tuple1.append(m.hexdigest()[:6])
                        m = hashlib.md5()
                        m.update(temp_str2.encode(encoding_format))
                        tuple1.append(m.hexdigest()[:6])
                        tuple1.append("data")
                        line_tuple_str = str(key) + "__split__" + str(line) + "__split__data"
                        func_sem[line_tuple_str] = tuple1
                        if str(key) not in func_merge.keys():
                            func_merge[str(key)] = []
                        if str(line) not in func_merge.keys():
                            func_merge[str(line)] = []
                        func_merge[str(key)].append(tuple1)
                        func_merge[str(line)].append(tuple1)
    return func_syn, func_sem, func_merge

def modifyNotOperator(method_list, file_name):
    os.system("./joern --script getCondition_per.sc --params cpgFile=cpg.bin,filePath=method_filtered.json")
    i=0
    for method_info in method_list:
        try:
            NT_coor_list_old = []
            with open("conditionJson/CONDITION" + i.__str__() + ".json", "r", encoding="utf8") as f:
                NT_coor_list_old = json.load(f)
            GT_coor_list_old = []
            LT_coor_list_old = []
            with open("conditionJson/GET" + i.__str__() + ".json", "r", encoding="utf8") as f:
                GT_coor_list_old = json.load(f)
            with open("conditionJson/LET" + i.__str__() + ".json", "r", encoding="utf8") as f:
                LT_coor_list_old = json.load(f)
            fp = []
            with open(temp_work_dir + "normalized/" + file_name, "r", encoding=encoding_format) as f:
                fp = f.readlines()
                already = set()
                for condition in NT_coor_list_old:
                    for key in condition.keys():
                        if key in already:
                            continue
                        k = key.find("!")
                        if k != -1 and key[k+1]=='!':                            
                            stmt = key[k+2:]
                            fp[condition[key]-1] = fp[condition[key]-1].replace(key, stmt)
                            already.add(key[k+1:])
                            continue                        
                        if "&&" in key or "||" in key or "=" in key:
                            continue
                        if "!" in key[k+1:]:
                            continue
                        stmt = key[k+1:] + "==0"
                        fp[condition[key]-1] = fp[condition[key]-1].replace(key, stmt)
                for GT in GT_coor_list_old:
                        for key in GT:
                            Larg = key.split(">=")[0]
                            Rarg = key.split(">=")[1]
                            stmt = "{0}>{1}||{0}=={1}".format(Larg,Rarg)
                            fp[GT[key]-1] = fp[GT[key]-1].replace(key,stmt)
                for LT in LT_coor_list_old:
                    for key in LT:
                        Larg = key.split("<=")[0]
                        Rarg = key.split("<=")[1]
                        stmt = "{0}<{1}||{0}=={1}".format(Larg,Rarg)
                        fp[LT[key]-1] = fp[LT[key]-1].replace(key,stmt)
            with open(temp_work_dir + "normalized/" + file_name, "w", encoding=encoding_format) as f:
                f.writelines(fp)
            with open(temp_work_dir + "temp/" + file_name, "r", encoding=encoding_format) as f:
                fp = f.readlines()
                already = set()
                for condition in NT_coor_list_old:
                    for key in condition.keys():
                        if key in already:
                            continue
                        k = key.find("!")
                        if k != -1 and key[k+1]=='!':                            
                            stmt = key[k+2:]
                            fp[condition[key]-1] = fp[condition[key]-1].replace(key, stmt)
                            already.add(key[k+1:])
                            continue                        
                        if "&&" in key or "||" in key or "=" in key:
                            continue
                        if "!" in key[k+1:]:
                            continue
                        stmt = key[k+1:] + "==0"
                        fp[condition[key]-1] = fp[condition[key]-1].replace(key, stmt)
                for GT in GT_coor_list_old:
                        for key in GT:
                            Larg = key.split(">=")[0]
                            Rarg = key.split(">=")[1]
                            stmt = "{0}>{1}||{0}=={1}".format(Larg,Rarg)
                            fp[GT[key]-1] = fp[GT[key]-1].replace(key,stmt)
                for LT in LT_coor_list_old:
                    for key in LT:
                        Larg = key.split("<=")[0]
                        Rarg = key.split("<=")[1]
                        stmt = "{0}<{1}||{0}=={1}".format(Larg,Rarg)
                        fp[LT[key]-1] = fp[LT[key]-1].replace(key,stmt)
            with open(temp_work_dir + "temp/" + file_name, "w", encoding=encoding_format) as f:
                f.writelines(fp)
            i+=1
        except Exception as e:
            print(str(e))
            print("Error when detecting file:" + file_name + " ,the method is " + method_info[0] + " at line " + method_info[1].__str__())
    os.system("./joern-parse \"" + temp_work_dir + "temp/" + file_name+"\"")

def generate_signature_in_file(detect_dir, file, cnt, gcc):
    file_name = file.split("/")[-1]
    extension = ["c", "cpp", "c++", "cc", "C"]
    if file_name.split(".")[-1].strip() not in extension:
        return

    method_list = []
    method_list = detect_get_method_list(detect_dir, file, method_list, gcc)
    if method_list is None:
        return
    if gcc:
        modifyNotOperator(method_list, file_name)
    os.system("./joern --script slice_per.sc --params cpgFile=cpg.bin,filePath=method_filtered.json")
    os.system("./joern --script normalize_per.sc --params cpgFile=cpg.bin,filePath=method_filtered.json")
    i=0
    index_to_file_dict={}
    for method_info in method_list:
        cnt += 1
        detect_normalize1(file_name, i)
        cdg_map, ddg_map = detect_slicing1(i)
        func_syn, func_sem, func_merge = detect_generate_signature(file_name, method_info, cdg_map, ddg_map,work_dir, gcc)
        with open(tempSignature + cnt.__str__()+".json","w") as f:
            json.dump({"func_syn":func_syn,"func_sem":func_sem,"func_merge":func_merge,"file_name":file,"method_name":method_info[0],"line_number":method_info[1].__str__()},f)
        index_to_file_dict[cnt]={"file_name":file,"method_name":method_info[0],"line_number":method_info[1].__str__()}
        i+=1
    os.system("rm cpg.bin")
    os.system("rm -rf workspace/cpg.bin*")
    return index_to_file_dict


def detect_file(detect_dir, file, CVEList):
    ans_list = {}
    try:
        total_index_to_method_dict = {}
        index_to_method_dict = {}
        index_to_method_dict=generate_signature_in_file(detect_dir, file,len(total_index_to_method_dict), True)
        for index in index_to_method_dict:
            total_index_to_method_dict[index]=index_to_method_dict[index]
    except Exception as e:
        print("Error when detect file " + file +  " exception is ")
        print(e)
    sus_method_dict={}
    for index in total_index_to_method_dict.keys():
        with open(tempSignature + index.__str__()+".json","r") as f:
            sus_method_dict[index]=json.load(f)
    index1=0
    total=len(CVEList)
    for CVE in CVEList:
        index1 += 1
        if not os.path.exists(pagerank_location_prefix + CVE + ".json"):
            continue
        with open(pagerank_location_prefix + CVE + ".json", "r") as f:
            temp_dict = json.load(f)
            key_point_list = []
            a = sorted(temp_dict.items(), key=lambda x: x[1], reverse=True)
            if a[0][1] < pagerank_threshold:
                for item in a:
                    if item[1] == a[0][1]:
                        key_point_list.append(item[0])
            else:
                for func in temp_dict.keys():
                    if temp_dict[func] >= pagerank_threshold:
                        key_point_list.append(func)
            key_point_list = list(set(key_point_list))
        if CVE not in ans_list.keys():
            ans_list[CVE] = {}
        with open(signature_path+CVE+".json","r") as f:
            sig=json.load(f)
            match_dict={}
            with open(progress_file,"a") as f:
                now_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                f.write("["+now_time+"]"+" Matching "+CVE+" now. Progress:"+index1.__str__()+"/"+total.__str__()+"\n")
            for key in sig.keys():
                if key not in key_point_list[CVE]:
                    continue
                if key not in ans_list[CVE].keys():
                    ans_list[CVE][key] = {}
                if key.count("__split__")>=2 and not key.startswith("del"):
                    delete_lines=sig[key]["deleteLines"]
                    vul_syn=sig[key]["vul_syn"]
                    vul_sem=sig[key]["vul_sem"]
                    vul_merge = sig[key]['vul_merge']
                    pat_syn=sig[key]["pat_syn"]
                    pat_sem=sig[key]["pat_sem"]
                    pat_merge = sig[key]['pat_merge']
                    if len(vul_sem)==0:
                        continue
                    split_list=key.split("__split__")
                    match_dict[split_list[0]+"__split__"+split_list[2]]=[]
                    for index in sus_method_dict:
                        sus_method_syn=copy.deepcopy(sus_method_dict[index]["func_syn"])
                        sus_method_sem=copy.deepcopy(sus_method_dict[index]["func_sem"])
                        sus_method_merge=copy.deepcopy(sus_method_dict[index]["func_merge"])
                        method_name = sus_method_dict[index]["method_name"]
                        if method_name not in  ans_list[CVE][key].keys():
                            ans_list[CVE][key][method_name] = {}
                        ans_list[CVE][key][method_name]["line_number"] = sus_method_dict[index]["line_number"]
                        is_match=True
                        for line in delete_lines:
                            flag = False
                            match_id = 0
                            for id in sus_method_syn:
                                if line == sus_method_syn[id]:
                                    flag = True
                                    match_id = id
                                    break
                            if not flag:
                                is_match = False
                                break
                            else:
                                del sus_method_syn[match_id]
                        ans_list[CVE][key][method_name]["del_gcc"] = is_match
                        sus_method_syn=copy.deepcopy(sus_method_dict[index]["func_syn"])
                        cnt_vul_syn,match_dict_syn = matchSyn(sus_method_syn.copy(),vul_syn.copy(),vul_merge.copy(),sus_method_merge.copy())
                        if len(set(vul_syn)) > 0 and cnt_vul_syn / len(vul_syn) <= th_syn_v:
                            is_match=False   
                            ans_list[CVE][key][method_name]["vul_syn_gcc"] = is_match
                        else:
                            ans_list[CVE][key][method_name]["vul_syn_gcc"] = True

                        if len(vul_sem) > 0 and matchSem(sus_method_sem.copy(),vul_sem,vul_merge, match_dict_syn,sus_method_merge.copy(),False):
                            is_match=False
                            ans_list[CVE][key][method_name]["vul_sem_gcc"] = is_match
                        else:
                            ans_list[CVE][key][method_name]["vul_sem_gcc"] = True
                        sus_method_syn=copy.deepcopy(sus_method_dict[index]["func_syn"])
                        sus_method_sem=copy.deepcopy(sus_method_dict[index]["func_sem"])
                        cnt_pat_syn,match_dict_syn = matchSyn(sus_method_syn.copy(),pat_syn.copy(),pat_merge.copy(),sus_method_merge.copy())

                        if len(set(pat_syn)) > 0 and cnt_pat_syn / len(pat_syn) > th_syn_p:
                            is_match=False
                            ans_list[CVE][key][method_name]["pat_syn_gcc"] = is_match
                        else:
                            ans_list[CVE][key][method_name]["pat_syn_gcc"] = True

                        if  len(pat_sem) > 0 and matchSem(sus_method_sem.copy(),pat_sem,pat_merge, match_dict_syn,sus_method_merge.copy(),True):
                            is_match=False
                            ans_list[CVE][key][method_name]["pat_sem_gcc"] = is_match
                        else:
                            ans_list[CVE][key][method_name]["pat_sem_gcc"] = True

                elif key.startswith("del__split__"):

                    syn_sig=sig[key]["syn"]
                    sem_sig=sig[key]["sem"]
                    split_list=key.split("__split__")
                    if len(sem_sig)==0:
                        continue

                    match_dict[split_list[1]+"__split__"+split_list[2]]=[]
                    for index in sus_method_dict:
                        sus_method_syn=copy.deepcopy(sus_method_dict[index]["func_syn"])
                        sus_method_sem=copy.deepcopy(sus_method_dict[index]["func_sem"])
                        method_name = sus_method_dict[index]["method_name"]
                        if method_name not in  ans_list[CVE][key].keys():
                            ans_list[CVE][key][method_name] = {}
                        ans_list[CVE][key][method_name]["line_number"] = sus_method_dict[index]["line_number"]
                        is_match=True
                        cnt_vul_syn = 0
                        for syn in syn_sig:
                            tar_key = -1
                            for syn_key in sus_method_syn:
                                if syn == sus_method_syn[syn_key]:
                                    tar_key = syn_key
                                    break
                            if tar_key != -1:
                                del sus_method_syn[tar_key]
                                cnt_vul_syn += 1
                    
                        if len(set(syn_sig)) > 0 and cnt_vul_syn / len(syn_sig) <= th_syn_v:
                            is_match=False
                            ans_list[CVE][key][method_name]["syn_gcc"] = is_match
                        else:
                            ans_list[CVE][key][method_name]["syn_gcc"] = True

                        cnt_match_vul_sem = 0
                        for three_tuple_pat_sem in sem_sig:
                            tar_key = -1
                            for syn_key in sus_method_sem:
                                if three_tuple_pat_sem == sus_method_sem[syn_key]:
                                    tar_key = syn_key
                                    break
                            if tar_key != -1:
                                del sus_method_sem[tar_key]
                                cnt_match_vul_sem += 1
                        if len(sem_sig)!=0 and cnt_match_vul_sem/len(sem_sig)<=th_syn_v:
                            is_match=False
                            ans_list[CVE][key][method_name]["sem_gcc"] = is_match
                        else:
                            ans_list[CVE][key][method_name]["sem_gcc"] = True
    try:
        total_index_to_method_dict = {}
        index_to_method_dict = {}
        index_to_method_dict=generate_signature_in_file(detect_dir, file,len(total_index_to_method_dict), False)
        for index in index_to_method_dict:
            total_index_to_method_dict[index]=index_to_method_dict[index]
    except Exception as e:
        print("Error when detect file " + file +  " exception is ")
        print(e)
    sus_method_dict={}
    for index in total_index_to_method_dict.keys():
        with open(tempSignature + index.__str__()+".json","r") as f:
            sus_method_dict[index]=json.load(f)
    for CVE in CVEList:
        if not os.path.exists(pagerank_location_prefix + CVE + ".json"):
            continue
        with open(pagerank_location_prefix + CVE + ".json", "r") as f:
            temp_dict = json.load(f)
            key_point_list = []
            a = sorted(temp_dict.items(), key=lambda x: x[1], reverse=True)
            if a[0][1] < pagerank_threshold:
                for item in a:
                    if item[1] == a[0][1]:
                        key_point_list.append(item[0])
            else:
                for func in temp_dict.keys():
                    if temp_dict[func] >= pagerank_threshold:
                        key_point_list.append(func)
            key_point_list = list(set(key_point_list))
        if CVE not in ans_list.keys():
            ans_list[CVE] = {}
        with open(signature_path_old+CVE+".json","r") as f:
            sig=json.load(f)
            for key in sig.keys(): 
                if key not in key_point_list[CVE]:
                    continue
                if key not in ans_list[CVE].keys():
                    ans_list[CVE][key] = {}
                if key.count("__split__")>=2 and not key.startswith("del"):

                    delete_lines=sig[key]["deleteLines"]
                    vul_syn=sig[key]["vul_syn"]
                    vul_sem=sig[key]["vul_sem"]
                    vul_merge = sig[key]['vul_merge']
                    pat_syn=sig[key]["pat_syn"]
                    pat_sem=sig[key]["pat_sem"]
                    pat_merge = sig[key]['pat_merge']
                    if len(vul_sem)==0:
                        continue
                    for index in sus_method_dict:
                        sus_method_syn=copy.deepcopy(sus_method_dict[index]["func_syn"])
                        sus_method_sem=copy.deepcopy(sus_method_dict[index]["func_sem"])
                        sus_method_merge=copy.deepcopy(sus_method_dict[index]["func_merge"])
                        method_name = sus_method_dict[index]["method_name"]
                        is_match=True
                        if method_name not in  ans_list[CVE][key].keys():
                            ans_list[CVE][key][method_name] = {}
                        ans_list[CVE][key][method_name]["line_number"] = sus_method_dict[index]["line_number"]
                        is_match=True
                        for line in delete_lines:
                            flag = False
                            match_id = 0
                            for id in sus_method_syn:
                                if line == sus_method_syn[id]:
                                    flag = True
                                    match_id = id
                                    break
                            if not flag:
                                is_match=False
                                break
                            else:
                                del sus_method_syn[match_id]
                        ans_list[CVE][key][method_name]["del"] = is_match
                        sus_method_syn=copy.deepcopy(sus_method_dict[index]["func_syn"])

                        cnt_vul_syn,match_dict_syn = matchSyn(sus_method_syn.copy(),vul_syn.copy(),vul_merge.copy(),sus_method_merge.copy())
                        if len(set(vul_syn)) > 0 and cnt_vul_syn / len(vul_syn) <= th_syn_v:
                            is_match=False
                            ans_list[CVE][key][method_name]["vul_syn"] = False
                        else:
                            ans_list[CVE][key][method_name]["vul_syn"] = True
                        if len(vul_sem) != 0 and matchSem(sus_method_sem.copy(),vul_sem,vul_merge, match_dict_syn,sus_method_merge.copy(),False):
                            is_match=False
                            ans_list[CVE][key][method_name]["vul_sem"] = False
                        else:
                            ans_list[CVE][key][method_name]["vul_sem"] = True
                        sus_method_syn=copy.deepcopy(sus_method_dict[index]["func_syn"])
                        sus_method_sem=copy.deepcopy(sus_method_dict[index]["func_sem"])

                        cnt_pat_syn,match_dict_syn = matchSyn(sus_method_syn.copy(),pat_syn.copy(),pat_merge.copy(),sus_method_merge.copy())

                        if len(set(pat_syn)) > 0 and cnt_pat_syn / len(pat_syn) > th_syn_p:
                            is_match=False
                            ans_list[CVE][key][method_name]["pat_syn"] = is_match
                        else:
                            ans_list[CVE][key][method_name]["pat_syn"] = True

                        if  len(pat_sem)!=0 and matchSem(sus_method_sem.copy(),pat_sem,pat_merge, match_dict_syn,sus_method_merge.copy(),True):
                            is_match=False
                            ans_list[CVE][key][method_name]["pat_sem"] = False
                        else:
                            ans_list[CVE][key][method_name]["pat_sem"] = True                           
                elif key.startswith("del__split__"):

                    syn_sig=sig[key]["syn"]
                    sem_sig=sig[key]["sem"]
                    if len(sem_sig)==0:
                        continue
                    for index in sus_method_dict:
                        sus_method_syn=copy.deepcopy(sus_method_dict[index]["func_syn"])
                        sus_method_sem=copy.deepcopy(sus_method_dict[index]["func_sem"])
                        method_name = sus_method_dict[index]["method_name"]
                        if method_name not in ans_list[CVE][key].keys():
                            ans_list[CVE][key][method_name] = {}
                        ans_list[CVE][key][method_name]["line_number"] = sus_method_dict[index]["line_number"]
                        is_match=True
                        cnt_vul_syn = 0
                        for syn in syn_sig:
                            tar_key = -1
                            for syn_key in sus_method_syn:
                                if syn == sus_method_syn[syn_key]:
                                    tar_key = syn_key
                                    break
                            if tar_key != -1:
                                del sus_method_syn[tar_key]
                                cnt_vul_syn += 1
                    
                        if len(set(syn_sig)) > 0 and cnt_vul_syn / len(syn_sig) <= th_syn_v:
                            is_match=False
                            ans_list[CVE][key][method_name]["syn"] = False
                        else:
                            ans_list[CVE][key][method_name]["syn"] = True

                        cnt_match_vul_sem = 0
                        for three_tuple_pat_sem in sem_sig:
                            tar_key = -1
                            for syn_key in sus_method_sem:
                                if three_tuple_pat_sem == sus_method_sem[syn_key]:
                                    tar_key = syn_key
                                    break
                            if tar_key != -1:
                                del sus_method_sem[tar_key]
                                cnt_match_vul_sem += 1
                        if len(sem_sig)!=0 and cnt_match_vul_sem/len(sem_sig)<=th_syn_v:
                            is_match=False
                            ans_list[CVE][key][method_name]["sem"] = is_match
                        else:
                            ans_list[CVE][key][method_name]["sem"] = True
    return ans_list
    
def matchSem(func_sem,sig_sem,sig_merge, match_dict_source,func_merge,isPatch):
    max_sem_cnt = [0]
    match_one2one = {}
    vis = {}
    flag_empty = {}
    flag_full = {}
    if match_dict_source == {}:
        if isPatch:
            return False
        else:
            return True
    match_dict = {}
    sortKeys = sorted(list(match_dict_source.keys()))
    empty_cnt = 0
    for key in sortKeys:
        match_dict[key] = sorted(match_dict_source[key])
        if len(match_dict[key])==0:
            empty_cnt += 1
    stack = [(match_one2one, vis, match_dict,flag_empty,flag_full,0)]
    while stack:
        match_one2one, vis, match_dict,flag_empty,flag_full,pre_key = stack.pop()
        sem_match_cnt = 0
        keys = match_dict.keys() - match_one2one.keys()
        if len(keys) == empty_cnt:
            for three_tuple_sig_sem_key in sig_sem:
                line_info = three_tuple_sig_sem_key.split("__split__")
                lineNumber1 = line_info[0]
                lineNumber2 = line_info[1]
                relation = line_info[2]
                if lineNumber1 in match_one2one.keys() and lineNumber2 in match_one2one.keys():
                    relation_key = match_one2one[lineNumber1] + "__split__" + match_one2one[lineNumber2] + "__split__" + relation
                    if relation_key in func_sem.keys() and func_sem[relation_key] == sig_sem[three_tuple_sig_sem_key]:
                        sem_match_cnt += 1
            max_sem_cnt.append(sem_match_cnt)
            if isPatch:
                if len(set(sig_sem)) > 0 and max(max_sem_cnt) / len(sig_sem) > th_sem_p:
                    return True
            else:
                if len(set(sig_sem)) > 0 and max(max_sem_cnt) / len(sig_sem) > th_sem_v:
                    return False
        else:
            key = sorted(list(keys))[0]
            if len(match_dict[key])==0:
                i = 0
                while i < len(list(keys)) and len(match_dict[key])==0 and sig_merge[key] == []:
                    key = sorted(list(keys))[i]
                    i += 1
                if (len(match_dict[key])==0 and sig_merge[key] != []):
                    if isPatch:
                        if len(set(sig_sem)) > 0 and max(max_sem_cnt) / len(sig_sem) > th_sem_p:
                            return True
                        else:
                            return False
                    else:
                        if len(set(sig_sem)) > 0 and max(max_sem_cnt) / len(sig_sem) <= th_sem_v:
                            return True
                        else:
                            return False
            if (key not in flag_empty.keys() or flag_empty[key] == -1) and (key not in flag_full.keys() or flag_full[key] == -1):
                 for line in match_dict[key]:
                    if line not in vis.keys() or vis[line] == False:
                        if pre_key != 0 and (int(pre_key)-int(key))*(int(match_one2one[pre_key])-int(line)) <= 0:
                            continue
                        if sig_merge[key]==[]:
                            match_one2one[key] = line
                            vis[line] = True
                            flag_empty[key] = line
                            flag_full[key] = line
                            stack.append((match_one2one.copy(), vis.copy(), match_dict,flag_empty.copy(),flag_full.copy(),key))
                            break
                        elif len(match_dict[key]) >= 30:
                            match_one2one[key] = line
                            vis[line] = True
                            flag_empty[key] = line
                            flag_full[key] = line
                            stack.append((match_one2one.copy(), vis.copy(), match_dict,flag_empty.copy(),flag_full.copy(),key))
                            break
                        else:
                            match_one2one[key] = line
                            vis[line] = True
                            flag_empty[key] = -1
                            flag_full[key] = -1
                            stack.append((match_one2one.copy(), vis.copy(), match_dict,flag_empty.copy(),flag_full.copy(),key))
                            vis[line] = False

    for three_tuple_sig_sem_key in sig_sem:
        line_info = three_tuple_sig_sem_key.split("__split__")
        lineNumber1 = line_info[0]
        lineNumber2 = line_info[1]
        relation = line_info[2]
        if lineNumber1 in match_one2one.keys() and lineNumber2 in match_one2one.keys():
            relation_key = match_one2one[lineNumber1] + "__split__" + match_one2one[lineNumber2] + "__split__" + relation
            if relation_key in func_sem.keys() and func_sem[relation_key] == sig_sem[three_tuple_sig_sem_key]:
                sem_match_cnt += 1
    max_sem_cnt.append(sem_match_cnt)
    if isPatch:
        if len(set(sig_sem)) > 0 and max(max_sem_cnt) / len(sig_sem) > th_sem_p:
            return True
        else:
            return False
    else:
        if len(set(sig_sem)) > 0 and max(max_sem_cnt) / len(sig_sem) <= th_sem_v:
            return True
        else:
            return False   

    
def matchSyn(sus_method_syn,sig_syn,sig_merge,sus_method_merge):
    time0 = time.time()
    cnt_sig_syn = 0
    match_syn = {}
    vis_func = []
    vis_syn = []
    syn_dict = {}
    target_dict = {}
    for syn_key in sig_syn:
        if sig_syn[syn_key] not in syn_dict.keys():
            syn_dict[sig_syn[syn_key]] = []
            syn_dict[sig_syn[syn_key]].append(syn_key)
        else:
            syn_dict[sig_syn[syn_key]].append(syn_key)
    for tar_key in sus_method_syn:
        if sus_method_syn[tar_key] not in target_dict.keys():
            target_dict[sus_method_syn[tar_key]] = []
            target_dict[sus_method_syn[tar_key]].append(tar_key)
        else:
            target_dict[sus_method_syn[tar_key]].append(tar_key)
    cnt = 0
    for syn_hash in syn_dict:
        if syn_hash not in target_dict.keys():
            continue
        if len(target_dict[syn_hash]) >= 30:
            cnt_sig_syn += 1
            for syn_line in syn_dict[syn_hash]:
                match_syn[syn_line] = target_dict[syn_hash]
            continue
        for syn_line in syn_dict[syn_hash]:
            for func_line in target_dict[syn_hash]:
                merge_func = copy.deepcopy(sus_method_merge)
                if func_line not in merge_func.keys() and sig_merge[syn_line]==[]:
                    if syn_line not in match_syn.keys():
                            match_syn[syn_line] = []
                    if func_line not in vis_func and syn_line not in vis_syn:
                        cnt_sig_syn += 1
                        vis_func.append(func_line)
                        vis_syn.append(syn_line)
                    match_syn[syn_line].append(func_line)
                    continue
                elif func_line not in merge_func.keys():
                    continue
                cnt_match_vul_syn_merge = 0
                for three_tuple_vul_sem in sig_merge[syn_line]:
                    cnt += 1
                    if three_tuple_vul_sem in merge_func[func_line]:
                        cnt_match_vul_syn_merge += 1
                        merge_func[func_line].remove(three_tuple_vul_sem)
                if len(sig_merge[syn_line]) != 0 and cnt_match_vul_syn_merge / len(sig_merge[syn_line]) >= th_ce:
                    if syn_line not in match_syn.keys():
                        match_syn[syn_line] = []
                    if func_line not in vis_func and syn_line not in vis_syn:
                        cnt_sig_syn += 1
                        vis_func.append(func_line)
                        vis_syn.append(syn_line)
                    match_syn[syn_line].append(func_line)
                elif len(sig_merge[syn_line]) == 0:
                    if syn_line not in match_syn.keys():
                        match_syn[syn_line] = []
                    if func_line not in vis_func and syn_line not in vis_syn:
                        cnt_sig_syn += 1
                        vis_func.append(func_line)
                        vis_syn.append(syn_line)
                    match_syn[syn_line].append(func_line)
    time1 = time.time()
    return cnt_sig_syn,match_syn 


def filter_multi(detect_dir, signature_info):
    with open(saga_file,"r") as f:
        lines=f.readlines()
    i=0
    CVE_dict={}
    while i<len(lines):
        if lines[i].startswith("CVE-"):
            CVE=lines[i].split(" ")[0]
            CVE_dict[CVE]=[]
            cnt=int(lines[i][:-1].split(" ")[1])
            for j in range(i+1,i+cnt+1):
                content=lines[j]
                if content[-1]=="\n":
                    content=content[:-1]
                CVE_dict[CVE].append(content)
            i=i+cnt+1
    CVE_dict_line_number={}
    file_hash_line_number_to_index_dict={}
    index_to_file_dict={}
    os.chdir(work_dir)
    os.system("rm -rf "+detect_dir+"/codeclone/")
    os.system("cp -r " + vulFileMulti + " " + detect_dir + "/codeclone/")
    os.chdir(saga_dir)
    os.system("rm -rf tokenData/")
    os.system("java -jar SAGACloneDetector-small.jar " + detect_dir + "/")

    with open("./result/MeasureIndex.csv", "r", encoding="utf8") as f:
        lines = f.readlines()
        for line in lines:
            split_list = line.split(",")
            index = split_list[0]
            file_name = split_list[1]
            start_line = split_list[2]
            index_to_file_dict[index]=file_name
            if "codeclone" in file_name:
                file_hash = file_name.split("/")[-1].split(".")[0]
                file_hash_line_number_to_index_dict[file_hash+"__split__"+start_line]=index
    for CVE in CVE_dict.keys():
        CVE_dict_line_number[CVE]=[]
        for ele in CVE_dict[CVE]:
            split_list=ele.split(" ")
            CVE_dict_line_number[CVE].append(file_hash_line_number_to_index_dict[split_list[0]+"__split__"+split_list[1]])
    zero_CVE_set=set()
    for CVE in CVE_dict_line_number.keys():
        if len(CVE_dict_line_number[CVE])==0:
            zero_CVE_set.add(CVE)
    for CVE in zero_CVE_set:
        del CVE_dict_line_number[CVE]
    clone_dict={}
    file_clone_dict = {}
    i=0
    with open("./result/type12_snippet_result.csv","r",encoding="utf8") as f:
        lines=f.readlines()
        while i<len(lines):
            temp=i
            while temp<len(lines) and lines[temp]!="\n":
                temp+=1
            repo_set=set()
            codeclone_set=set()
            for cur in range(i,temp):
                file_name=index_to_file_dict[lines[cur].split(",")[1]]
                if "codeclone" in file_name:
                    codeclone_set.add(lines[cur].split(",")[1])
                else:
                    repo_set.add(lines[cur].split(",")[1])
            for id in codeclone_set:
                if id not in clone_dict.keys():
                    clone_dict[id]=set()
                for id1 in repo_set:
                    clone_dict[id].add(id1)
            for id in repo_set:
                if id not in file_clone_dict.keys():
                    file_clone_dict[id] = set()
                for id1 in codeclone_set:
                    file_clone_dict[id].add(id1)
                if len(file_clone_dict[id])==0:
                    del file_clone_dict[id]
            i=temp+1
    i=0
    with open("./result/type3_snippet_result.csv","r",encoding="utf8") as f:
        lines=f.readlines()
        while i<len(lines):
            temp=i
            while temp<len(lines) and lines[temp]!="\n":
                temp+=1
            repo_set=set()
            codeclone_set=set()
            for cur in range(i,temp):
                file_name=index_to_file_dict[lines[cur].split(",")[1]]
                if "codeclone" in file_name:
                    codeclone_set.add(lines[cur].split(",")[1])
                else:
                    repo_set.add(lines[cur].split(",")[1])
            for id in codeclone_set:
                if id not in clone_dict.keys():
                    clone_dict[id]=set()
                for id1 in repo_set:
                    clone_dict[id].add(id1)
            for id in repo_set:
                if id not in file_clone_dict.keys():
                    file_clone_dict[id] = set()
                for id1 in codeclone_set:
                    file_clone_dict[id].add(id1)
                if len(file_clone_dict[id])==0:
                    del file_clone_dict[id]
            i=temp+1
    filtered_dict=dict()
    filtered_file_set=set()
    matched_file_dict = {}
    for id in file_clone_dict.keys():
        if "codeclone" in index_to_file_dict[id]:
            continue
        if index_to_file_dict[id] not in matched_file_dict.keys():
            matched_file_dict[index_to_file_dict[id]] = []
        for CVE in CVE_dict_line_number.keys():
            for cve_id in CVE_dict_line_number[CVE]:
                if cve_id in file_clone_dict[id]:
                    if CVE not in matched_file_dict[index_to_file_dict[id]]:
                        matched_file_dict[index_to_file_dict[id]].append(CVE)
        if len(matched_file_dict[index_to_file_dict[id]]) == 0:
            del matched_file_dict[index_to_file_dict[id]]

    for CVE in CVE_dict_line_number.keys():
        file_set=set()
        for id in CVE_dict_line_number[CVE]:
            if id in clone_dict.keys():
                for clone_id in clone_dict[id]:
                    if "codeclone" not in index_to_file_dict[clone_id]:
                        file_set.add(index_to_file_dict[clone_id])
                        filtered_file_set.add(index_to_file_dict[clone_id])
        if len(file_set)!=0:
            filtered_dict[CVE]=file_set
    if detect_dir.split("/")[-1].strip() == "":
        detect_dir = detect_dir.strip()[:-1]
    os.chdir(work_dir)
    index_file = 1
    matchLists = {}
    for file in filtered_file_set:
        print("{0}/{1} {2}".format(index_file,len(filtered_file_set), file))
        index_file += 1
        matchLists[file] = detect_file(detect_dir, file, filtered_dict)
    match_dict = checkResult(matchLists, signature_info)
    f = open("thrown_cve.pkl","rb")
    thrown_cve = pickle.load(f)
    f.close()
    if match_dict != {}:
        with open("resultMulti.txt","a",encoding="utf8") as f:
            for CVE in match_dict.keys():
                if CVE in thrown_cve:
                    continue
                f.write("Found "+CVE+" in "+detect_dir+"!\n")
                for key in match_dict[CVE]["match_dict"].keys():
                    if len(match_dict[CVE]["match_dict"][key]) > 5:
                        continue
                    f.write("Method "+key+" matches the following methods:\n")
                    for id in match_dict[CVE]["match_dict"][key]:
                        f.write("Method "+id[0]+" in file "+match_dict[CVE]["file"]+".\n")
                f.write("\n")

def checkResult(matchLists, signature_info):
    match_dict = {}
    for file in matchLists.keys():
        matchList = matchLists[file]
        for cve in matchList.keys():
            matchTypedict = {}
            is_match = False
            for sig_method in matchList[cve].keys():
                if sig_method.count("__split__")>=2 and not sig_method.startswith("del"):
                    if sig_method not in matchTypedict.keys():
                        matchTypedict[sig_method] = []
                    if sig_method not in signature_info[cve+".json"].keys():
                        continue
                    if "pure_sig" in signature_info[cve+".json"][sig_method].keys() and not signature_info[cve+".json"][sig_method]["pure_sig"] and "gcc_sig" in signature_info[cve+".json"][sig_method].keys() and not signature_info[cve+".json"][sig_method]["gcc_sig"]:
                        continue
                    elif "pure_sig" in signature_info[cve+".json"][sig_method].keys() and not signature_info[cve+".json"][sig_method]["pure_sig"] and "gcc_sig" not in signature_info[cve+".json"][sig_method].keys():
                        continue
                    elif "gcc_sig" in signature_info[cve+".json"][sig_method].keys() and not signature_info[cve+".json"][sig_method]["gcc_sig"] and "pure_sig" not in signature_info[cve+".json"][sig_method].keys():
                        continue
                    if "pure_sig" in signature_info[cve+".json"][sig_method].keys() and  "gcc_sig" in signature_info[cve+".json"][sig_method].keys():
                        if not signature_info[cve+".json"][sig_method]["pure_sig"] and signature_info[cve+".json"][sig_method]["gcc_sig"]:
                            for tar_method in matchList[cve][sig_method].keys():
                                if "pat_syn_gcc" in matchList[cve][sig_method][tar_method]:
                                    if matchList[cve][sig_method][tar_method]["pat_syn_gcc"] and matchList[cve][sig_method][tar_method]["pat_sem_gcc"] and matchList[cve][sig_method][tar_method]["vul_syn_gcc"] and matchList[cve][sig_method][tar_method]["vul_sem_gcc"] and matchList[cve][sig_method][tar_method]["del_gcc"]:
                                        matchTypedict[sig_method].append((tar_method, matchList[cve][sig_method][tar_method]["line_number"]))
                                        is_match = True
                            continue
                        if not signature_info[cve+".json"][sig_method]["gcc_sig"] and signature_info[cve+".json"][sig_method]["pure_sig"]:
                            for tar_method in matchList[cve][sig_method].keys():
                                if "pat_syn" in matchList[cve][sig_method][tar_method]:
                                    if matchList[cve][sig_method][tar_method]["pat_syn"] and matchList[cve][sig_method][tar_method]["pat_sem"] and matchList[cve][sig_method][tar_method]["vul_syn"] and matchList[cve][sig_method][tar_method]["vul_sem"] and matchList[cve][sig_method][tar_method]["del"]:
                                        matchTypedict[sig_method].append((tar_method, matchList[cve][sig_method][tar_method]["line_number"]))
                                        is_match = True
                            continue
                    methodName = getPureSigName(sig_method)
                    for tar_method in matchList[cve][sig_method].keys():
                        tarMethodName = getPureTarName(tar_method)
                        if "pat_syn" in matchList[cve][sig_method][tar_method].keys() and "pat_syn_gcc" in matchList[cve][sig_method][tar_method]:
                            if not matchList[cve][sig_method][tar_method]["pat_syn"] or not matchList[cve][sig_method][tar_method]["pat_sem"]:
                                continue
                            else:
                                if matchList[cve][sig_method][tar_method]["pat_syn"] and matchList[cve][sig_method][tar_method]["pat_sem"] and matchList[cve][sig_method][tar_method]["vul_syn"] and matchList[cve][sig_method][tar_method]["vul_sem"] and matchList[cve][sig_method][tar_method]["del"]:
                                    matchTypedict[sig_method].append((tar_method, matchList[cve][sig_method][tar_method]["line_number"]))
                                    is_match = True
                                    continue
                                if matchList[cve][sig_method][tar_method]["pat_syn_gcc"] and matchList[cve][sig_method][tar_method]["pat_sem_gcc"] and matchList[cve][sig_method][tar_method]["vul_syn_gcc"] and matchList[cve][sig_method][tar_method]["vul_sem_gcc"] and matchList[cve][sig_method][tar_method]["del_gcc"]:
                                    matchTypedict[sig_method].append((tar_method, matchList[cve][sig_method][tar_method]["line_number"]))
                                    is_match = True
                        elif "pat_syn" in matchList[cve][sig_method][tar_method].keys():
                            if not matchList[cve][sig_method][tar_method]["pat_syn"] or not matchList[cve][sig_method][tar_method]["pat_sem"]:
                                continue
                            if matchList[cve][sig_method][tar_method]["pat_syn"] and matchList[cve][sig_method][tar_method]["pat_sem"] and matchList[cve][sig_method][tar_method]["vul_syn"] and matchList[cve][sig_method][tar_method]["vul_sem"] and matchList[cve][sig_method][tar_method]["del"]:
                                matchTypedict[sig_method].append((tar_method, matchList[cve][sig_method][tar_method]["line_number"]))
                                is_match = True
                                continue
                            matchMethodGcc = ""
                            for matchSigMethod in matchList[cve].keys():
                                matchMethodName = getPureSigName(matchSigMethod)
                                if matchSigMethod != sig_method and methodName == matchMethodName:
                                    if tar_method not in matchList[cve][matchSigMethod].keys():
                                        matchTarMethodGcc = ""
                                        for matchTarMethod in matchList[cve][sig_method].keys():
                                            matchMethodTarName = getPureTarName(matchTarMethod)
                                            if matchTarMethod != tar_method and matchMethodTarName == matchTarMethodGcc and "pat_syn_gcc" in matchList[cve][sig_method][matchMethodTarName].keys() and "pat_syn" not in matchList[cve][sig_method][matchMethodTarName].keys():
                                                matchTarMethodGcc = matchTarMethod
                                                break
                                        
                                        if matchTarMethodGcc == "":
                                            continue
                                        if "pat_syn_gcc" in matchList[cve][matchSigMethod][matchTarMethodGcc].keys() and "pat_syn" not in matchList[cve][matchSigMethod][matchTarMethodGcc].keys():
                                            matchMethodGcc = matchSigMethod
                                            break
                                    else:
                                        if "pat_syn_gcc" in matchList[cve][matchSigMethod][tar_method].keys() and "pat_syn" not in matchList[cve][matchSigMethod][tar_method].keys():
                                            matchMethodGcc = matchSigMethod
                                            break
                            if matchMethodGcc != "":
                                if matchList[cve][matchMethodGcc][tar_method]["pat_syn_gcc"] and matchList[cve][matchMethodGcc][tar_method]["pat_sem_gcc"] and matchList[cve][matchMethodGcc][tar_method]["vul_syn_gcc"] and matchList[cve][matchMethodGcc][tar_method]["vul_sem_gcc"] and matchList[cve][matchMethodGcc][tar_method]["del_gcc"]:
                                    matchTypedict[sig_method].append((tar_method, matchList[cve][sig_method][tar_method]["line_number"]))
                                    is_match = True
                            else:
                                matchTarMethodGcc = ""
                                for matchTarMethod in matchList[cve][sig_method].keys():
                                    matchMethodTarName = getPureTarName(matchTarMethod)
                                    if matchTarMethod != tar_method and matchMethodTarName == matchTarMethodGcc and "pat_syn_gcc" in matchList[cve][sig_method][matchMethodTarName].keys() and "pat_syn" not in matchList[cve][sig_method][matchMethodTarName].keys():
                                        matchTarMethodGcc = matchTarMethod
                                        break
                                if matchTarMethodGcc != "":
                                    if matchList[cve][sig_method][matchTarMethodGcc]["pat_syn_gcc"] and matchList[cve][sig_method][matchTarMethodGcc]["pat_sem_gcc"] and matchList[cve][sig_method][matchTarMethodGcc]["vul_syn_gcc"] and matchList[cve][sig_method][matchTarMethodGcc]["vul_sem_gcc"] and matchList[cve][sig_method][matchTarMethodGcc]["del_gcc"]:
                                        matchTypedict[sig_method].append((tar_method, matchList[cve][sig_method][tar_method]["line_number"]))
                                        is_match = True
                        elif "pat_syn_gcc" in matchList[cve][sig_method][tar_method]:
                            if matchList[cve][sig_method][tar_method]["pat_syn_gcc"] and matchList[cve][sig_method][tar_method]["pat_sem_gcc"] and matchList[cve][sig_method][tar_method]["vul_syn_gcc"] and matchList[cve][sig_method][tar_method]["vul_sem_gcc"] and matchList[cve][sig_method][tar_method]["del_gcc"]:
                                matchTypedict[sig_method].append((tar_method, matchList[cve][sig_method][tar_method]["line_number"]))
                                is_match = True
                                continue

                elif sig_method.startswith("del__split__"):
                    if "pure_sig" in signature_info[cve+".json"][sig_method].keys() and not signature_info[cve+".json"][sig_method]["pure_sig"] and "gcc_sig" in signature_info[cve+".json"][sig_method].keys() and not signature_info[cve+".json"][sig_method]["gcc_sig"]:
                        continue
                    elif "pure_sig" in signature_info[cve+".json"][sig_method].keys() and not signature_info[cve+".json"][sig_method]["pure_sig"] and "gcc_sig" not in signature_info[cve+".json"][sig_method].keys():
                        continue
                    elif "gcc_sig" in signature_info[cve+".json"][sig_method].keys() and not signature_info[cve+".json"][sig_method]["gcc_sig"] and "pure_sig" not in signature_info[cve+".json"][sig_method].keys():
                        continue
                    matchTypedict[sig_method] = []
                    for tar_method in matchList[cve][sig_method].keys():
                        if "syn_gcc" in matchList[cve][sig_method][tar_method].keys():
                            if matchList[cve][sig_method][tar_method]["syn_gcc"] and matchList[cve][sig_method][tar_method]["sem_gcc"]:
                                matchTypedict[sig_method].append((tar_method, matchList[cve][sig_method][tar_method]["line_number"]))
                                is_match = True
                        else:
                            if matchList[cve][sig_method][tar_method]["syn"] and matchList[cve][sig_method][tar_method]["sem"]:
                                matchTypedict[sig_method].append((tar_method, matchList[cve][sig_method][tar_method]["line_number"]))
                                is_match = True
            if is_match:
                if cve not in match_dict.keys():
                    match_dict[cve] = {}
                match_dict[cve]["match_dict"] = matchTypedict
                match_dict[cve]["file"] = file
    return match_dict
            

def getSignatureInfo():
    signature = signature_path_old
    signature_gcc = signature_path
    signautres = {}
    cves = os.listdir(signature_gcc)
    for i in tqdm(range(len(cves))):
        cve = cves[i]
        signautres[cve] = {}
        f = open(os.path.join(signature,cve))
        sigs = json.load(f)
        f.close()
        for key in sigs:
            if key not in signautres[cve].keys():
                signautres[cve][key] = {}
            if key.count("__split__")>=2 and not key.startswith("del"):
                if len(sigs[key]["vul_sem"])==0:
                    signautres[cve][key]["pure_sig"] = False
                    continue
                vul_syn=sigs[key]["vul_syn"]
                vul_sem=sigs[key]["vul_sem"]
                vul_merge = sigs[key]['vul_merge']
                pat_syn=sigs[key]["pat_syn"]
                pat_sem=sigs[key]["pat_sem"]
                pat_merge = sigs[key]['pat_merge']
                cnt_pat_syn,match_dict_syn = matchSyn(vul_syn.copy(),pat_syn.copy(),pat_merge.copy(),vul_merge.copy())
                if len(set(pat_syn)) > 0 and cnt_pat_syn / len(pat_syn) > th_syn_p and len(set(vul_syn)) > 0 and (len(vul_syn) - cnt_pat_syn) / len(vul_syn) <= th_syn_v:
                    signautres[cve][key]["pure_sig"] = False
                    continue
                signautres[cve][key]["pure_sig"] = True
            elif key.startswith("del__split__"):
                if len(sigs[key]["sem"])==0:
                    signautres[cve][key]["pure_sig"] = False
                    continue
                signautres[cve][key]["pure_sig"] = True
        f = open(os.path.join(signature_gcc,cve))
        sigs = json.load(f)
        f.close()
        for key in sigs:
            if key not in signautres[cve].keys():
                signautres[cve][key] = {}
            if key.count("__split__")>=2 and not key.startswith("del"):
                if len(sigs[key]["vul_sem"])==0:
                    signautres[cve][key]["gcc_sig"] = False
                    continue
                vul_syn=sigs[key]["vul_syn"]
                vul_sem=sigs[key]["vul_sem"]
                vul_merge = sigs[key]['vul_merge']
                pat_syn=sigs[key]["pat_syn"]
                pat_sem=sigs[key]["pat_sem"]
                pat_merge = sigs[key]['pat_merge']
                cnt_pat_syn,match_dict_syn = matchSyn(vul_syn.copy(),pat_syn.copy(),pat_merge.copy(),vul_merge.copy())
                if len(set(pat_syn)) > 0 and cnt_pat_syn / len(pat_syn) > th_syn_p and len(set(vul_syn)) > 0 and (len(vul_syn) - cnt_pat_syn) / len(vul_syn) <= th_syn_v:
                    signautres[cve][key]["gcc_sig"] = False
                    continue
                signautres[cve][key]["gcc_sig"] = True
            elif key.startswith("del__split__"):
                if len(sigs[key]["sem"])==0:
                    signautres[cve][key]["gcc_sig"] = False
                    continue
                signautres[cve][key]["gcc_sig"] = True
    with open("sig_info.json","w") as f:
        json.dump(signautres,f)

def getPureSigName(sig_method):
    methodNames = sig_method.split("__split__")[-1].split(" ")
    methodName = ""
    for i in range(len(methodNames)):
        if "(" in methodNames[i]:
            methodName = methodNames[i-1]
            break
    return methodName

def getPureTarName(sig_method):
    methodNames = sig_method.split(" ")
    methodName = ""
    for i in range(len(methodNames)):
        if "(" in methodNames[i]:
            j = i-1
            while j >= 0 and methodNames[j] == "":
                j -= 1
            methodName = methodNames[j]
            break
    return methodName


if __name__ == '__main__':
    detect_dir = sys.argv[1]
    getSignatureInfo()
    signature_info = {}
    f = open("sig_info.json","r")
    signature_info = json.load(f)
    try:
        time0 = time.time()
        filter_multi(detect_dir, signature_info)
        with open(progress_file,"a") as f:
            f.write(f"Elapsed time: {time.time()-time0}\n")
    except Exception as e:
        print("Error when detect repo " + dir)
        print(e)