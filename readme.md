The widespread use of open-source software (OSS) has led to extensive code reuse, making vulnerabilities in OSS significantly pervasive. The vulnerabilities due to code reuse in OSS are commonly known as vulnerable code clones (VCCs) or recurring vulnerabilities. Existing approaches primarily employ clone-based techniques to detect recurring vulnerabilities through matching vulnerable functions in software projects. These techniques do not incorporate specially-designed mechanisms for vulnerabilities with multiple fixing functions (VM). Typically, they generate a signature for each fixing function and report VM using a matching-one-in-all approach. However, the variation in vulnerability context across diverse fixing functions results in varying accuracy levels in detecting VMs, potentially limiting the effectiveness of existing methods.

In this paper, we introduce VMUD, a novel approach for detecting Vulnerabilities with Multiple Fixing Functions (VM). VMUD identifies vulnerable function clones (VCCs) through function matching similar to existing methods. However, VMUD takes a different approach by only selecting the critical functions from VM for signature generation, which are a subset of the fixing functions. This step ensures VMUD to focus on fixing functions that offer sufficient knowledge about the VM. To cope with the potential decrease in recall due to excluding the remaining fixing functions, VMUD employs semantic equivalent statement matching using these critical functions. It aims to uncover more VM by creating two signatures of each critical function and match precisely by contextual semantic equivalent statement mapping on the two signatures. Our evaluation has demonstrated that VMUD surpasses state-of-the-art vulnerability detection approaches by 17.6% in terms of F1-Score. Furthermore, VMUD has successfully detected 275 new VM across 84 projects, with 42 confirmed cases and 5 assigned CVE identifiers.

The paper has been submitted to CCS 2024.    

This page lists the supplementary materiales including the dataset, source code and reproducing scripts of our paper.

### Recent News

- [2024-06-22]📢📢📢we have released [documents](doc/ProgramRephrasing.xlsx) about program Rephrasing.
- [2024-06-22]📢📢📢we have released the progress of the [GroundTruth Construction](https://github.com/vmud20/vmud20.github.io/tree/main/dataset/GroundTruth), which can help you understand our GroundTruth.
- [2024-06-22]📢📢📢we have done an extra [experiments](#📢📢📢**EXTRA experiments to show vmud's state-of-the-art.****) to show vmud's state-of-the-art.
- [2024-06-20]📢📢📢we have conducted a broad [survey](#📢📢📢 broad survey) about vulnerability detection and released the paper list. 
- [2024-04-30]🚀🚀🚀our paper is submitted to CCS 2024.
- [2024-04-27]🚀🚀🚀we have released out [Groundtruth](evaluation/RQ1/results/GT.csv), thanks for two annotators and one mediator!
- [2024-04-25]🚀🚀🚀our tool have been released, welcome to reproduce our tool and give us some suggestions.

### ✨✨WHAT IS NEW

##### 📢📢📢**EXTRA experiments to show vmud's state-of-the-art.**

- We have done an extra ablation experiment which can show the effectiveness of semantic equivalence. To get the ablation study results of VMUD w/o PR+CESM. We have released the [code](evaluation/RQ3/w_o_PR_CESM.py), you can just replace the *detection.py* file in VMUD with the [code](evaluation/RQ3/w_o_PR_CESM.py) to reproduce our results. The step is similar to the vmud.

- We have evaluated CodeQL, Fortify, Checkmarx on our 84 projects. They only identify 6 true positives. The results of Fortify and Checkmarx is shown in [Fortify_results](https://github.com/vmud20/vmud20.github.io/tree/main/evaluation/static_tool_analysis/Fortify) and [checkmarx_results](https://github.com/vmud20/vmud20.github.io/tree/main/evaluation/static_tool_analysis/checkmarx) respectively. As for CodeQL, we have done it by GitHub Action embedded in the CodeQL tool, you can reproduce our results by [Github](https://github.com). The overall results is shown in [static_analysis_tool_results.xlsx](evaluation/static_tool_analysis/static_analysis_tool_results.xlsx).
- We have conducted an extra experiments to show the effectiveness of Pagerank algorithm for critical function selection, including HITS algorithm and heuristic rules.
  - **HITS algorithm**: the HITS (Hyperlink-Induced Topic Search) algorithm is a link analysis algorithm that assigns authority and hub scores to web pages based on the structure of hyperlinks,aiming to find an important webpage. To reproduce the results of our experiment, you can just replace the [pagerank.py](vmud/signatureGeneration/pagerank.py) with [HITS.py](evaluation/pagerank_evaluation/HITS.py) when you run VMUD. The step is similar to the vmud. After our experiments, we find that using the HITS algorithm resulted in a 0.10 decrease in precision and 0.03 decrease in recall.
  - **Heuristic rules**: we define heuristic rules as a set of guidelines where if all the functions along a call path are matched during the matching process, it indicates a potential vulnerability in the target project.To reproduce the results of our experiment, you can just replace the  [pagerank.py](vmud/signatureGeneration/pagerank.py) with [HITS.py](evaluation/pagerank_evaluation/heuristic/callgraph.py) and replace [detection.py](vmud/Detection/detection.py) with [heuristic.py](evaluation/pagerank_evaluation/heuristic/heuristic.py) when you run VMUD. The step is similar to the vmud. After our experiments, we find that using heuristic rules resulted in a 0.09 decrease in precision and 0.20 decrease in recall.


##### 📢📢📢 broad survey

- Firstly, we identified 1,401 [papers](docs/literature_all.csv) by searching the academic databases Google Scholar, Semantic Scholar, Scopus, and Crossref using the keywords "vulnerability," "detection," "vulnerable," and "discovery." Then, following V1Scan (2023), DeepDFA (2024), we identified 387 [papers](docs/literature_software_vulnerability.csv) from 1,401 papers on software vulnerability. Among them, we excluded 67 empirical studies, 196 domain-specific papers, 97 deep-learning-based papers before DeepDFA. The remaining 27 papers include regular papers, short papers, preprints across various venues.

### Dataset

- **VM Signature**: VMud starts by giving an input as a CVE ID and traces patches to find the vulnerability-fixing commit in two ways. First, it searches the CVE ID in open-source software repositories’ histories with vulnerability keywords and filters out irrelevant commits. The irrelevant commits include reverted commits, merging commits, etc. Second, it leverages the National Vulnerability Database (NVD) reference pages for silent fixes (*i.e.*, commits without explicit CVE ID mentions). This database provides valuable metadata and refer encing pages related to CVE fixes. Finally, we collect 810 VMs, the dataset can be download [here](dataset/VMs.json), and you can get original signature *Xorg* and rephrased signature *Xrep* which is generated by [SignatureGenetation.py](vmud/fingerprint/SignatureGenetation.py) in [signature_org](https://github.com/vmud20/vmud20.github.io/tree/main/dataset/signature_org) and [signature_rep](https://github.com/vmud20/vmud20.github.io/tree/main/dataset/signature_rep).
- **Target Project Selection.** We established three criteria for project selection. Firstly, projects should be written in C/C++. Secondly, they should be popular in popularity and span diverse domains. Thirdly, they should be actively maintained. Subsequently, we collected 972 projects from GitHub by querying the Top 1000 popular projects ranked by their stars using GitHub API. These projects encompass areas such as databases, operating systems, image processing, reverse development, etc. The project list is shown [here](dataset/projects.json).
- **Ground Truth generation: **Two annotators and one mediator have over three years’ expertise in software security. Two annotators have submitted CVEs previously. It took 3 rounds. In the [first](dataset/GroundTruth/first_round.xlsx) and [second](dataset/GroundTruth/second_round.xlsx) rounds, they had 16 and 5 disagreements. The disagreements stemmed from different understanding in vulnerability context and triggering conditions. 

### Runtime environment:

1. **Joern :** we use the version of 1.1.1377. 

   The installation process for Joern can be found at https://docs.joern.io/installation.

   To install and run Joern, JDK 11 environment is required.

2. **doxygen:**  we use the version of 1.10. 

   The installation process for Joern can be found at https://github.com/doxygen/doxygen.

3. **Python**: The required libraries for the version include json, os, hashlib, re, sys, queue, xml, pickle and networkx.

4. **ctags:** The installation process for ctags can be found at https://github.com/universal-ctags/ctags.

### Source code

Our code can be download [here](https://github.com/vmud20/vmud20.github.io/tree/main/vmud), The code is divided into two directories: *signatureGeneration* and *VMDetector*. To generate signatures, execute the Python script named ***SignatureGenetation.py***. Besides, to conduct VM detection for a specific project, run the Python script ***detection.py*** to obtain the detection results.

##### VM Signature generation

- **Input:** CVE-ID, Project's path affected by CVE, patch commit file path (patch commit file can be obtained through git show + commit hash)

- **Output**: 

  - a directory named *vulFileMulti*: Files containing vulnerable functions
  - a file named *sagaMulti.json*: The line number information of the vulnerability method in the file
  - the signature file named *CVE-XXXX-XXXX.json*
  - PageRank score of each modified function(**For the vulnerability patches we have used in evaluation, we have already generated all [PageRank score](https://github.com/vmud20/vmud20.github.io/tree/main/dataset/pagerank) of each modified function in the patch.**)
  - all macros involved in patch files(**For the vulnerability patches we have collected, we have already extracted all [macros](https://github.com/vmud20/vmud20.github.io/tree/main/dataset/macros4sig) involved in each patch.**)

- **signature generation:**

  - **List of File:**

    - *normalize.sc*: scala script to extract the positional information of formal parameters, local variables, type declarations, and method invocations using Joern
    - *slice.sc*: scala script to get the method's Program Dependency Graph(PDG) via Joern
    - *metadata.sc*: scala script to retrieve the list of methods for a specified file using Joern
    - *get_condition.sc*: scala script to get the positional information of expression which need to rephrase via Joern
    - *getMacros.py*: python script to extract all macros involved in patch files.
    - *gen_fingerprint_multi_rep.py*: python script to get the rephrased signature *Xrep*
    - *gen_fingerprint_multi_org.py*: python script to get the original signature *Xorg*
    - *SignatureGenetation.py*： python script for signature generation
    - *config_sigs.json*: configuration file for signature generation
    - *pagerank.py*: python script to get the PageRank score of each modified function in the patch.
    - *config.py*: configuration file for PageRank score generation.
    - *saga*: a clone detection tool saga
  
  - **configuration for signature generation:** the modifiable parameters include:
  
    - *signature_path*: the absolute path to store signature
    - *work_path*: the absolute path to the directory of joern-cli
    - *macros*: the absolute path to store macros
    - *ctagsPath*: the absolute path to the directory of ctags tool
    - *saga_path*: the absolute path to the directory of SAGA
  
  - **configuration for PageRank:**
  
    - *Doxygen_conf_location*: the absolute path to the directory of doxygen.
    - *work_path*: the absolute path to the directory of joern-cli
    - *error_log_file*:the path to the error log file
    - *timeout_repo_list_file*: the file path to record repository information for timeouts
    - *method_info_location*: the file path to record method information
    - *no_define_location_prefix*: the directory path to store the call graph information
    - *jump_threshold*: call graph jump threshold, the default is 3
    - *subprocess_exec_max_time_sec*: the time limit for call graph generation, specified in seconds, the default is 4 hours
    - *subprocess_exam_time_sec*: the polling frequency for call graph generation process, specified in seconds, the default is 1minute
    - *file_num_threshold*: the scale of files involved in the call graph, the default is 5000
    - *pagerank_location_prefix*: the directory path to store the PageRank score files.
  
  - **generation step:** please place the [files](https://github.com/vmud20/vmud20.github.io/tree/main/vmud/signatureGeneration) into the *joern-cli* directory. Ensure that the directory includes executable files such as *joern*, *joern-parse*, and *joern-flow*. After complete the relevant entries in the configuration file, just run the following command:
  
    ```
    python SignatureGenetation.py CVE_ID commit_file_location git_repo_location
    ```
  
    - **CVE_ID**: the CVE-ID corresponding to the patch file.
  
    - **commit_file_location**: the absolute path to the file storing GitHub commit content.
  
    - **git_repo_location:** the absolute path to the directory of the GitHub repository corresponding to the CVE.

##### Detection

- **List of File:**

  - *normalize_per.sc*: scala script to extract the positional information of formal parameters, local variables, type declarations, and method invocations using Joern
  - *slice_per.sc*: scala script to get the method's Program Dependency Graph(PDG) via Joern
  - *metadata.sc*: scala script to retrieve the list of methods for a specified file using Joern
  - *getCondition_per.sc*: scala script to get the positional information of expression which need to rephrase via Joern
  - *thrown_cve.pkl*: the list of CVEs removed due to the limitations of the Joern and Doxygen tools
  - *sagaMulti.json*: the line number information of the vulnerability method in the file
  - *saga*: a clone detection tool saga
  - *vulFileMulti*: files containing vulnerable functions
  - *config.json*: configuration for detector
  - *detection.py*: python script to implement vmud
  - *Instructions for Utilizing SAGA.md*: a instruction for SAGA
  
- **configuration for VMUD Detection:**

  - *signature_path*: the absolute path to store rephrased signature *Xrep*
  - *work_path*: the absolute path to the directory of joern-cli
  - *saga_path*: the absolute path to the directory of SAGA
  - *progress_file*: the path of log file
  - *saga_multi*: the path of *sagaMulti.json*
  - *vulFileMulti*: the path of *vulFileMulti*
  - *ctagsPath*: the absolute path to the directory of ctags tool
  - *tempSignature*: the path to store the detected repository's signature
  - *signature_path_org*:  the absolute path to store original signature *Xorg*
  - *targetRepoMacros*:  the absolute path to store macros
  - *pagerank_location_prefix*: the directory path to store the PageRank score files.
  - *pagerank_threshold*: PageRank score threshold, the default is 0.018
  - *th_syn_v*: the threshold for syn(*X_tgt* , *X_src_V* ), the default is 0.7
  - *th_sem_v*: the threshold for sem(*X_tgt* , *X_src_V* ), the default is 0.6
  - *th_syn_p*: the threshold for syn(*X_tgt* , *X_src_P* ), the default is 0.3
  - *th_sem_p*: the threshold for sem(*X_tgt* , *X_src_P* ), the default is 0.4
  - *th_ce*: the threshold for CESM(*X_tgt* , *X_src* ) , the default is 0.6

- **VMUD Detection**

  1. In the *joern-cli* directory (which should include executable files such as *joern*, *joern-parse*, and *joern-flow*), create five folders named *temp*, *slicingJson*, *normalizeJson*, *normalized*, and *conditionJson*. 

  2. Please place the following files in the *joern-cli* directory: *normalize_per.sc*, *detection.py*, *slice_per.sc*, *metadata.sc*, *getCondition_per.sc*, *thrown_cve.pkl* and *config.json*. The folders *vulFileMulti* and *ctags*, along with the *saga* folder and *sagaMulti.json* file, have no specific placement restriction.
  
  3. After complete the relevant entries in the configuration file, just run the following command:

     ```bash
     python detection.py detect_dir
     ```
  
     The tool will output the detected recurring vulnerability results to the *resultMulti.txt* file in the *joern-cli* directory.

     - *detect_dir* refers to absolute path for repository that needed to be detected

### Evaluation

The evaluation contains RQ1, RQ2, RQ3, RQ4 and RQ5, the data and code can download [here](https://github.com/vmud20/vmud20.github.io/tree/main/evaluation), after downloading, you can easily replicat the result on our paper.

- ** Dataset**

  - **Number and Percentage of Functions in Collected VM**: 

    To replicate our results for the number and Percentage of Functions in Collected VM, which is shown in table 3 in our paper, please use :

    ```bash
    python Number_of_functions_in_VMs.py signaturePath_org signaturePath_rep
    ```

    - **signaturePath_org** refers to the absolute path of the original signature *Xorg*, in our evaluation, it's [signature_org](https://github.com/vmud20/vmud20.github.io/tree/main/dataset/signature_org).
    - **signaturePath_rep** refers to the absolute path of the original signature *Xrep*, in our evaluation, it's [signature_rep](https://github.com/vmud20/vmud20.github.io/tree/main/dataset/signature_rep).

  - **Number of Files and Lines of Code (LOC) on our Evaluated Dataset:**

    To replicate our results for the Number of Files and Lines of Code (LOC) on our Evaluated Dataset, which is shown in Figure 4 in our paper, please    run the following steps:

    1.  clone the repositories and checkout to the corresponding versions. The information of repositories' URL and the corresponding versions can be found in [this file](https://github.com/vmud20/vmud20.github.io/tree/main/dataset/projects.json).
    2. Use **cloc** to analyse these repositories and then you will gain the raw information which is Number of Files and Lines of Code (LOC) on our Evaluated Dataset. It is shown in [cloc directory](https://github.com/vmud20/vmud20.github.io/tree/main/evaluation/dataset/data/cloc).
    3. Run the python script ***getrepoCloc.py*** and then you will gain [repoFileNum.json](evaluation/dataset/data/repoFileNum.json) and  [repoCodeNum.json](evaluation/dataset/data/repoCodeNum.json).
    4. To get the [Figure 4](evaluation/dataset/figs/rq0_repoInfo.pdf), please run the python script ***RQ0_dataset.py***.

- **RQ1: Effectiveness Evaluation.**

  - ***Accuracy Results***

    As for **VUDDY**, we cloned the open-source code of [Vuddy](https://github.com/squizz617/vuddy), following their [instructions](https://github.com/squizz617/vulnDBGen/blob/f4cb690e43e5c4fe212a85317782cfe13a3c9bab/docs/%EC%B7%A8%EC%95%BD%EC%A0%90%20%EB%8D%B0%EC%9D%B4%ED%84%B0%EB%B2%A0%EC%9D%B4%EC%8A%A4%20%EC%83%9D%EC%84%B1%20%EC%86%94%EB%A3%A8%EC%85%98%20%EB%A7%A4%EB%89%B4%EC%96%BC%20V1.0.pdf), generated our own signatures and conducted detection on the all [projects](https://github.com/vmud20/vmud20.github.io/tree/main/dataset/projects.json), obtaining the detection [results](evaluation/RQ1/results/results_vuddy.txt), then we conducted manual validation of all positive results by the authors to confirm the presence of VM, and then get the confirmed [results](evaluation/RQ1/results/results_vuddy.xlsx).

    As for **MVP**, cause it's not open-sourced, we just implemented MVP based on their paper. Then we use it to generate signatures and detected all [projects](https://github.com/vmud20/vmud20.github.io/tree/main/dataset/projects.json), obtaining the [results](evaluation/RQ1/results/results_MVP.txt), then we conducted manual validation of all positive results by the authors to confirm the presence of VM, and then get the confirmed [results](evaluation/RQ1/results/results_MVP.csv).

    As for **Movery**, as Movery does not provide open-source code for signature generation, we intersected our collected CVEs with their dataset to ensure a fair evaluation, which resulted in a Diminished VM Dataset of 144 VM signatures, the intersected CVEs is shown in [intersection_cve.pkl](). We just test [MOVERY](https://hub.docker.com/r/seunghoonwoo/movery-public) using Docker,  obtaining the [results](evaluation/RQ1/results/results_movery.txt), then we conducted manual validation of all positive results by the authors to confirm the presence of VM, and then get the confirmed [results](evaluation/RQ1/results/results_movery.csv).

    As for **V1scan**, We just run V1scan using docker following the [instructions](https://github.com/WOOSEUNGHOON/V1SCAN-public/blob/main/README.md),  obtaining the [results](evaluation/RQ1/results/results_v1scan.txt), then we conducted manual validation of all positive results by the authors to confirm the presence of VM, and then get the confirmed [results](evaluation/RQ1/results/results_v1scan.csv).

    As for **VMUD**, we run our tool to detect all [projects](https://github.com/vmud20/vmud20.github.io/tree/main/dataset/projects.json), obtaining the [results](evaluation/RQ1/results/results_vmud.txt), then we conducted manual validation of all positive results by the authors to confirm the presence of VM, and then get the confirmed [results](evaluation/RQ1/results/results_vmud.xlsx).

    After that, we merge all positive results and get the [Groundtruth](evaluation/RQ1/results/GT.csv). 

    Above all, we get the results of **matching-one-function-in-all approach**. To get the results of  **matching-all-functions approach**, we analyzed the results file and removed all positive results where there was not a complete match with all modified methods in the patch. Then we get the results shown in Table 4.

  - ***Accuracy Per Project***

    To get the accuracies of each tool’s results on every project containing VM, please use:

    ```
    python get_repo_results.py
    ```

    Then you will get the results *i.e.*[results_repo_movery.json](evaluation/RQ1/results/results_repo_movery.json), [results_repo_MVP.json](evaluation/RQ1/results/results_repo_MVP.json), [results_repo_vmud.json](evaluation/RQ1/results/results_repo_vmud.json), [results_repo_v1scan.json](evaluation/RQ1/results/results_repo_v1scan.json),[results_repo_vuddy.json](evaluation/RQ1/results/results_repo_vuddy.json).
    
    To get the Figure 5 of our paper, please use:
    
    ```bash
    python RQ1_accuracy.py
    ```
    
    To get the Figure 6 of our paper, please use:
    
    ```bash
    python RQ1_accuracyBar.py
    ```

  - ***Comparison with Learning-based Approaches***

    Additionally, we compared two learning-based tools using precision and recall w.r.t vulnerable functions. We directly utilized the trained models of [DeepDFA](https://github.com/ISU-PAAL/DeepDFA) and [SySeVR](https://github.com/SySeVR/SySeVR) on their respective datasets and used our ground truth as the testing dataset, the results is shown in Table 6.


  **We used the default configurations outlined in the original papers for all selected tools.**

- **RQ2: Robustness Evaluation.**

  To assess VMud’s robustness, we examine its accuracy across VM with varying numbers of fixing functions. 

  ```bash
  python get_cve_results.py
  ```

  Then you will get the [results](evaluation/RQ2/results/resultsCVE_vmud.json), which is shown in Table 7.

- **RQ3: Ablation Study.**

  - To get the ablation study results which is shown in Table 8 of our paper, just replace the *detection.py* file in VMUD with [w_o_CFS.py](evaluation/RQ3/w_o_CFS.py), [w_o_PR.py](evaluation/RQ3/w_o_PR.py), [w_o_CESM.py](evaluation/RQ3/w_o_CESM.py), respectively, and following the usage instructions outlined above to detect all [projects](https://github.com/vmud20/vmud20.github.io/tree/main/dataset/projects.json).

- **RQ4: Threshold Sensitivity.**

  We conducted a sensitivity analysis to assess the impact of various thresholds (*th_pr* , *th_syn_V*, *th_sem_V*, *th_syn_P* , *th_sem_P*, *th_ce*) on VMud’s performance. Just modify the corresponding configurations in ***config.json*** and proceed to detect all [projects](https://github.com/vmud20/vmud20.github.io/tree/main/dataset/projects.json). Then we will get the [results](https://github.com/vmud20/vmud20.github.io/tree/main/evaluation/RQ4/datas) depends on the [Groundtruth](evaluation/RQ1/results/GT.csv). To get [Figure 7](https://github.com/vmud20/vmud20.github.io/tree/main/evaluation/RQ4/figs) in our paper, please run the python script ***RQ4_sensitivity.py***.

- **RQ5: Performance Evaluation.**

  The the time cost of VMud will output in the log file which you configured in the *config.json* when you detect the project using vmud. As for our evaluation for RQ5, we extract the cost time into [result_vmudTime.json](evaluation/RQ5/data/result_vmudTime.json). 

  Besides, as for Vuddy, MVP, Movery and V1scan, we can also extract the cost time from their log file. The cost time of detector using every tool is shown [here](https://github.com/vmud20/vmud20.github.io/tree/main/evaluation/RQ5/data).

  To get box plot illustrating the time spent on VM detection in each project, please use:

  ```bash
  python RQ5_performance.py
  ```

  Then you will get [Figure 8](evaluation/RQ5/figs/rq5_performance.pdf)