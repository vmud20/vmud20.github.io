import matplotlib.pyplot as plt
import numpy as np
import json
from typing import List, Tuple, Any
import FontSizeAll
import constants

plt.rcParams["font.family"] = FontSizeAll.FONT_FAMILY
plt.rcParams["figure.figsize"] = (6, 3)
plt.rcParams["lines.linewidth"] = FontSizeAll.Line_WIDTH
plt.rcParams['axes.unicode_minus'] = FontSizeAll.AXES_UNICODE_MINUS


# plt.rcParams['text.usetex'] = True


def getrepoResults(fileName, discardRepo):
    TP = []
    FP = []
    FN = []
    repos = []
    with open(fileName, "r") as f:
        repoAccuracy = json.load(f)
        for repo in repoAccuracy.keys():
            if repo in discardRepo:
                continue
            repos.append(repo)
            TP.append(repoAccuracy[repo]["TP"])
            FP.append(-repoAccuracy[repo]["FP"])
            FN.append(-repoAccuracy[repo]["FN"])

    return TP, FP, FN, repos


def getDiscardRepo():
    discardRepo = set()
    with open("./results/results_repo_movery.json", "r") as f:
        repoAccuracy = json.load(f)
        for repo in repoAccuracy.keys():
            if repoAccuracy[repo]["TP"] == 0 and repoAccuracy[repo]["FP"] == 0:
                discardRepo.add(repo)
                continue
            if repoAccuracy[repo]["TP"] == 0 and repoAccuracy[repo]["FN"] == 0:
                discardRepo.add(repo)
                continue
    with open("./results/results_repo_v1scan.json", "r") as f:
        repoAccuracy = json.load(f)
        for repo in repoAccuracy.keys():
            if repoAccuracy[repo]["TP"] == 0 and repoAccuracy[repo]["FP"] == 0:
                discardRepo.add(repo)
                continue
            if repoAccuracy[repo]["TP"] == 0 and repoAccuracy[repo]["FN"] == 0:
                discardRepo.add(repo)
                continue

    with open("./results/results_repo_vuddy.json", "r") as f:
        repoAccuracy = json.load(f)
        for repo in repoAccuracy.keys():
            if repoAccuracy[repo]["TP"] == 0 and repoAccuracy[repo]["FP"] == 0:
                discardRepo.add(repo)
                continue
            if repoAccuracy[repo]["TP"] == 0 and repoAccuracy[repo]["FN"] == 0:
                discardRepo.add(repo)
                continue
    with open("./results/results_repo_MVP.json", "r") as f:
        repoAccuracy = json.load(f)
        for repo in repoAccuracy.keys():
            if repoAccuracy[repo]["TP"] == 0 and repoAccuracy[repo]["FP"] == 0:
                discardRepo.add(repo)
                continue
            if repoAccuracy[repo]["TP"] == 0 and repoAccuracy[repo]["FN"] == 0:
                discardRepo.add(repo)
                continue
    with open("./results/results_repo_vmud.json", "r") as f:
        repoAccuracy = json.load(f)
        for repo in repoAccuracy.keys():
            if repoAccuracy[repo]["TP"] == 0 and repoAccuracy[repo]["FP"] == 0:
                discardRepo.add(repo)
                continue
            if repoAccuracy[repo]["TP"] == 0 and repoAccuracy[repo]["FN"] == 0:
                discardRepo.add(repo)
                continue
    return discardRepo


def drawScatter():

    discardRepo = getDiscardRepo()
    TP_ours, FP_ours, FN_ours, repos_ours = getrepoResults("./results/results_repo_vmud.json", discardRepo)
    TP_movery, FP_movery, FN_movery, repos_movery = getrepoResults("./results/results_repo_movery.json", discardRepo)
    TP_v1scan, FP_v1scan, FN_v1scan, repos_v1scan = getrepoResults("./results/results_repo_v1scan.json", discardRepo)
    TP_MVP, FP_MVP, FN_MVP, repos_MVP = getrepoResults("./results/results_repo_MVP.json", discardRepo)
    TP_vuddy, FP_vuddy, FN_vuddy, repos_vuddy = getrepoResults("./results/results_repo_vuddy.json", discardRepo)
    TP = [TP_ours, TP_vuddy, TP_MVP, TP_v1scan]
    FP = [FP_ours, FP_vuddy, FP_MVP, FP_v1scan]
    FN = [FN_ours, FN_vuddy, FN_MVP, FN_v1scan]
    repos = [repos_ours, repos_vuddy, repos_MVP, repos_v1scan]
    figsName = ["rq1_repoBarVmud","rq1_repoBarVuddy","rq1_repoBarMVP","rq1_repoBarV1scan"]
    for i in range(len(TP)):
        plt.figure()
        x_label = np.arange(1, len(TP[i]) + 1, 1)
        bar_width = 0.25
        plt.ylim([-30, 30])
        plt.xticks(np.arange(1, len(repos[i]) + 1, 1), np.arange(1, len(repos[i]) + 1, 1), fontsize=8.5, rotation=30,
                   fontfamily=FontSizeAll.FONT_FAMILY)
        plt.yticks(np.arange(-30, 40, 10), [30, 20, 10, 0, 10, 20, 30], fontsize=8.5,
                   fontfamily=FontSizeAll.FONT_FAMILY)
        plt.bar(x_label, TP[i], color=constants.line_color_rq1[4], label="TP", width=bar_width)
        plt.bar(x_label - bar_width, FP[i], color=constants.line_color_rq1[1], label="FP", width=bar_width)
        plt.bar(x_label + bar_width, FN[i], color=constants.line_color_rq1[2], label="FN", width=bar_width)
        plt.xlabel("Id. of Projects", fontsize=12, fontfamily=FontSizeAll.FONT_FAMILY)
        plt.ylabel("Number (\#)", fontsize=12, fontfamily=FontSizeAll.FONT_FAMILY)
        plt.legend()
        TICK_THICK = 1.0
        TICK_LENGTH = 1.5
        plt.gca().yaxis.set_tick_params(
            width=TICK_THICK, length=TICK_LENGTH, direction='in')
        plt.gca().xaxis.set_tick_params(
            width=TICK_THICK, length=TICK_LENGTH, direction='in')
        plt.grid(True, axis='y') 
        plt.grid(True, axis='x', which='minor') 
        plt.savefig(f'./figs/{figsName[i]}.pdf',
                    format='pdf', bbox_inches='tight')


if __name__ == "__main__":
    drawScatter()
