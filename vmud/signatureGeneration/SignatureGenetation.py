import gen_fingerprint_multi_org
import gen_fingerprint_multi_rep
import sys
import json
import pagerank
import getMacros

file = open("./config_sigs.json")
info = json.load(file)
work_dir = info["work_path"]
signature_path = info["signature_path"]
macros_path = info["macros"]
saga_dir = info["saga_path"]
file.close()


if __name__ == "__main__":
    CVE_ID = sys.argv[1]
    commit_file_location = sys.argv[2]
    git_repo_location = sys.argv[3]
    gen_fingerprint_multi_org.gen_fingerprint(CVE_ID, commit_file_location, git_repo_location, work_dir)
    gen_fingerprint_multi_rep.gen_fingerprint(CVE_ID, commit_file_location, git_repo_location, work_dir)
    gen_fingerprint_multi_org.get_vul_file(work_dir, commit_file_location, git_repo_location)
    gen_fingerprint_multi_org.get_method_line_multi(CVE_ID, commit_file_location, git_repo_location, work_dir)
    gen_fingerprint_multi_org.get_saga_line()
    pagerank.pageranMain(CVE_ID, commit_file_location, git_repo_location)
    getMacros.macrosMain(commit_file_location, git_repo_location)

