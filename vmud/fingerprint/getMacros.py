import subprocess
import os
import sys
import re
import time
import json

file = open("./config_sigs.json")
info = json.load(file)
savePath = info["macros"]
ctagsPath       = info["ctagsPath"]
encoding_format = "ISO-8859-1"
includeFiles = []
analysizedFiles = []
removedMacros = ["__FILE__", "__LINE__", "__DATE__", "__TIME__", "__STDC__", "__STDC_VERSION__", 
                "__cplusplus", "__GNUC__", "__GNUC_MINOR__", "__GNUC_PATCHLEVEL__", "__BASE_FILE__", "__FILE_NAME__", 
                "__INCLUDE_LEVEL__", "__VERSION__","__CHAR_UNSIGNED__", "__WCHAR_UNSIGNED__","__REGISTER_PREFIX__", "__USER_LABEL_PREFIX__"]

def removeComment(string):
	# Code for removing C/C++ style comments. (Imported from VUDDY and ReDeBug.)
	# ref: https://github.com/squizz617/vuddy
	c_regex = re.compile(
		r'(?P<comment>//.*?$|[{}]+)|(?P<multilinecomment>/\*.*?\*/)|(?P<noncomment>\'(\\.|[^\\\'])*\'|"(\\.|[^\\"])*"|.[^/\'"]*)',
		re.DOTALL | re.MULTILINE)
	return ''.join([c.group('noncomment') for c in c_regex.finditer(string) if c.group('noncomment')])

def getsMacros(repoPath, repoName, commitID, includeName):
	
	fileCnt  = 0
	lineCnt  = 0

	allMacs  = {}
	includes = set()
	macrosDict   = {}

	if not os.path.isdir(savePath + repoName):
		os.mkdir(savePath + repoName)
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
				filePath = os.path.join(prefix, analysisFile)
				if os.path.isfile(filePath):
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
						macro       = re.compile(r'(macro)')
						number 		= re.compile(r'(\d+)')
						tmpString	= ""
						lineCnt 	+= len(lines)
						fileCnt 	+= 1
						macros      = ""

						for i in allFuncs:
							elemList	= re.sub(r'[\t\s ]{2,}', '', i)
							elemList 	= elemList.split('\t')
							
							if i != '' and len(elemList) >= 6 and macro.fullmatch(elemList[3]):
								strStartLine 	 = int(number.search(elemList[4]).group(0))
								macrosName = elemList[0]
								if len(elemList) == 6:
									strEndLine 		 = int(number.search(elemList[5]).group(0))
								elif len(elemList) == 7:
									strEndLine 		 = int(number.search(elemList[6]).group(0))
								tmpString	= ""
								tmpString	= tmpString.join(lines[strStartLine - 1 : strEndLine])
								rawBody     = tmpString
								macros 		+= rawBody
							
								if filePath.replace('/', '@@') not in allMacs:
									allMacs[filePath.replace('/', '@@')] = []
								if macrosName not in macrosDict.keys():
									allMacs[filePath.replace('/', '@@')].append(rawBody)
									macrosDict[macrosName] = level
								elif macrosDict[macrosName] > level:
									allMacs[filePath.replace('/', '@@')].append(rawBody)
									macrosDict[macrosName] = level
							elif i != '' and len(elemList) >= 6 and macro.fullmatch(elemList[5]):
								strStartLine 	 = int(number.search(elemList[6]).group(0))
								macrosName = elemList[0]
								strEndLine 		 = int(number.search(elemList[7]).group(0))
								strEndLine 		 = int(number.search(elemList[7]).group(0))
								tmpString	= ""
								tmpString	= tmpString.join(lines[strStartLine - 1 : strEndLine])
								rawBody     = tmpString
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
				filePath = os.path.join(prefix,"include", analysisFile)
				if os.path.isfile(filePath):
					if filePath in analysizedFiles:
						break
					else:
						analysizedFiles.append(filePath)
					getIncludeFiles(filePath, prefix, level + 1)
					
					try:
						print(filePath)
						functionList 	= subprocess.check_output(ctagsPath + ' -f - --kinds-C=* --fields=neKSt "' + filePath + '"', stderr=subprocess.STDOUT, shell=True).decode(errors='replace')
						f = open(filePath, 'r', encoding = "UTF-8", errors='replace')

						lines 		= f.readlines()
						allFuncs 	= str(functionList).split('\n')
						macro       = re.compile(r'(macro)')
						number 		= re.compile(r'(\d+)')
						tmpString	= ""
						lineCnt 	+= len(lines)
						fileCnt 	+= 1
						macros      = ""

						for i in allFuncs:
							elemList	= re.sub(r'[\t\s ]{2,}', '', i)
							elemList 	= elemList.split('\t')
							
							if i != '' and len(elemList) >= 6 and macro.fullmatch(elemList[3]):								
								macrosName = elemList[0]
								strStartLine 	 = int(number.search(elemList[4]).group(0))
								if len(elemList) == 6:
									strEndLine 		 = int(number.search(elemList[5]).group(0))
								elif len(elemList) == 7:
									strEndLine 		 = int(number.search(elemList[6]).group(0))
								tmpString	= ""
								tmpString	= tmpString.join(lines[strStartLine - 1 : strEndLine])
								rawBody     = tmpString
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
				prefix = "/".join(prefix.split("/")[:-1])
			if not getInclude:
				includes.add(analysisFile)

	
	f = open(savePath + repoName + '/macro_' + commitID + "_" + includeName + '.h', 'w', encoding = "UTF-8")
	
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
			f.write(val)
	f.close()

def readCommit(location, git_repo_location, work_dir,is_new):
    with open(location, "r", encoding=encoding_format) as f:
        lines = f.readlines()
        files = []
        file_seperator = []
        for i in range(len(lines)):
            if lines[i].startswith("diff --git"):
                file_seperator.append(i)
        for i in range(len(file_seperator) - 1):
            files.append(lines[file_seperator[i] : file_seperator[i + 1] - 1])
        files.append(lines[file_seperator[len(file_seperator) - 1] : len(lines)])
    for file in files:
        parseFile(file, git_repo_location, work_dir, is_new)


def parseFile(file, git_repo_location, work_dir, is_new):
    extension = ["c", "cpp", "c++", "cc", "C"]
    info = {}
    info["oldFileName"] = file[0].split(" ")[2]
    info["newFileName"] = file[0].split(" ")[3][:-1]
    if (
        info["oldFileName"].split(".")[-1] not in extension
        or info["newFileName"].split(".")[-1] not in extension
    ):
        return
    if (
        "test" in info["oldFileName"]
        or "test" in info["newFileName"]
        or "tst" in info["oldFileName"]
        or "tst" in info["newFileName"]
    ):
        return
    info["oldCommit"] = file[1].split(" ")[1].split("..")[0]
    info["newCommit"] = file[1].split(" ")[1].split("..")[1]
    old_name = info["oldCommit"] + "-" + info["oldFileName"].split("/")[-1]
    new_name = info["newCommit"] + "-" + info["newFileName"].split("/")[-1]
    info["add"] = []
    info["delete"] = []
    os.chdir(git_repo_location)
    os.system("git show " + info["oldCommit"] + " > " + work_dir + "temp/" + old_name)
    os.system("git show " + info["newCommit"] + " > " + work_dir + "temp/" + new_name)
    if is_new:
        analysizedFiles.clear()
        includeFiles.append(("", info["newFileName"][2:], 0))
        prefix = "/".join(info["newFileName"][2:].split("/")[:-1])
        getIncludeFiles(work_dir + "temp/" + new_name, git_repo_location + "/" + prefix, 1)
        getsMacros(git_repo_location, inputRepo, commit_id, new_name)
    else:
        analysizedFiles.clear()
        includeFiles.append(("", info["oldFileName"][2:], 0))
        prefix = "/".join(info["oldFileName"][2:].split("/")[:-1])
        getIncludeFiles(work_dir + "temp/" + old_name, git_repo_location + "/" + prefix, 1)
        getsMacros(git_repo_location, inputRepo, commit_id + "~1", old_name)

def getIncludeFiles(fileName, prefix, level):
	with open(fileName, "r", encoding=encoding_format) as f:
		lines = f.readlines()
		for line in lines:
			if line.lstrip().startswith("#include"):
				file = line.replace("#include","").replace("\"","").replace("<","").replace(">"," ").strip().split(" ")[0]
				includeFiles.append((file, prefix, level))

if __name__ == '__main__':
    CVE_ID = sys.argv[1]
    commit_file_location = sys.argv[2]
    git_repo_location = sys.argv[3]
    current_working_directory = os.getcwd()
    inputRepo = git_repo_location.split("/")[-1].strip()
    os.chdir(git_repo_location)
    commit_id = commit_file_location.split("/")[-1].strip().replace("commit-","").replace(".txt","")
    os.system("git checkout -f %s"%commit_id)
    os.chdir(current_working_directory)
    readCommit(commit_file_location, git_repo_location, current_working_directory + "/", True)
    os.chdir(git_repo_location)
    os.system("git checkout -f %s~1"%commit_id)
    analysizedFiles1 = analysizedFiles
    analysizedFiles.clear()
    os.chdir(current_working_directory)
    readCommit(commit_file_location, git_repo_location, current_working_directory + "/", False)