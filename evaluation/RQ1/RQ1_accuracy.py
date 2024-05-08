import matplotlib.pyplot as plt
import numpy as np
import json
from typing import List, Tuple, Any
import FontSizeAll
import constants
from scipy.interpolate import make_interp_spline

plt.rcParams["font.family"] = FontSizeAll.FONT_FAMILY
plt.rcParams["figure.figsize"] = FontSizeAll.FIGURE_FIGSIZE
plt.rcParams["lines.linewidth"] = FontSizeAll.Line_WIDTH
plt.rcParams['axes.unicode_minus'] = FontSizeAll.AXES_UNICODE_MINUS
plt.rcParams['text.usetex'] = True


def getDiscardRepo():
    discardRepo = set()
    with open("./results/results_repo_v1scan.json", "r") as f:
        repoAccuracy = json.load(f)
        for repo in repoAccuracy.keys():
            if repoAccuracy[repo]["TP"] == 0 and repoAccuracy[repo]["FP"] == 0:
                discardRepo.add(repo)
                continue
            if repoAccuracy[repo]["TP"] == 0 and repoAccuracy[repo]["FN"] == 0:
                # print(repoAccuracy[repo])
                discardRepo.add(repo)
                continue

    with open("./results/results_repo_vuddy.json", "r") as f:
        repoAccuracy = json.load(f)
        for repo in repoAccuracy.keys():
            if repoAccuracy[repo]["TP"] == 0 and repoAccuracy[repo]["FP"] == 0:
                discardRepo.add(repo)
                continue
            if repoAccuracy[repo]["TP"] == 0 and repoAccuracy[repo]["FN"] == 0:
                # print(repoAccuracy[repo])
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


def getrepoResults(fileName, discardRepo):
    rec = []
    prec = []
    f1score = []
    with open(fileName, "r") as f:
        repoAccuracy = json.load(f)
        discard = 0
        for repo in repoAccuracy.keys():
            if repo in discardRepo:
                continue
            rec.append(repoAccuracy[repo]["recall"])
            prec.append(repoAccuracy[repo]["precision"])
            f1score.append(repoAccuracy[repo]["f1score"])
    # print(discard)
    return rec, prec, f1score


def getNum(f1score_ours):
    cnt = []
    for i in range(11):
        cnt.append(0)
    cnt_all = 0
    for f1score_our in f1score_ours:
        cnt_all += 1
        if f1score_our >= 0:
            cnt[0] += 1
        if f1score_our > 0.1:
            cnt[1] += 1
        if f1score_our > 0.2:
            cnt[2] += 1
        if f1score_our > 0.3:
            cnt[3] += 1
        if f1score_our > 0.4:
            cnt[4] += 1
        if f1score_our > 0.5:
            cnt[5] += 1
        if f1score_our > 0.6:
            cnt[6] += 1
        if f1score_our > 0.7:
            cnt[7] += 1
        if f1score_our > 0.8:
            cnt[8] += 1
        if f1score_our > 0.9:
            cnt[9] += 1
        if f1score_our >= 1:
            cnt[10] += 1

    return np.array(cnt)


def myPoly(x, y):
    unique_values, indices, counts = np.unique(x, return_index=True, return_counts=True)
    last_indices = indices + counts - 1
    y = y[last_indices]
    x = np.array(x)
    x = x[last_indices]
    fmodel0 = make_interp_spline(x, y)
    x_smooth = np.linspace(x.min(), x.max(), 10000)
    y_smooth = fmodel0(x_smooth)
    x_smooth = np.append(x_smooth, x.max())
    y_smooth = np.append(y_smooth, 0)
    x_smooth = np.insert(x_smooth, 0, 0)
    y_smooth = np.insert(y_smooth, 0, y_smooth.max())
    return x_smooth, y_smooth


def addLines(x, y):
    x_smooth = np.append(x, 0)
    y_smooth = np.append(y, y.max())
    x_smooth = np.insert(x_smooth, 0, x.max())
    y_smooth = np.insert(y_smooth, 0, 0)
    return x_smooth, y_smooth


def drawCDFf1score():
    plt.figure()
    discardRepo = getDiscardRepo()
    rec_ours, prec_ours, f1score_ours = getrepoResults("./results/results_repo_vmud.json", discardRepo)
    rec_movery, prec_movery, f1score_movery = getrepoResults("./results/results_repo_movery.json", discardRepo)
    rec_v1scan, prec_v1scan, f1score_v1scan = getrepoResults("./results/results_repo_v1scan.json", discardRepo)
    rec_MVP, prec_MVP, f1score_MVP = getrepoResults("./results/results_repo_MVP.json", discardRepo)
    rec_vuddy, prec_vuddy, f1score_vuddy = getrepoResults("./results/results_repo_vuddy.json", discardRepo)
    cnt_ours = getNum(f1score_ours)
    cnt_movery = getNum(f1score_movery)
    cnt_v1scan = getNum(f1score_v1scan)
    cnt_MVP = getNum(f1score_MVP)
    cnt_vuddy = getNum(f1score_vuddy)
    print(cnt_v1scan)
    y = np.arange(0, 1.1, 0.1)
    x_fit_ours, y_fit_ours = addLines(cnt_ours, y)
    x_fit_vuddy, y_fit_vuddy = addLines(cnt_vuddy, y)
    x_fit_MVP, y_fit_MVP = addLines(cnt_MVP, y)
    x_fit_v1scan, y_fit_v1scan = addLines(cnt_v1scan, y)
    x_fit_movery, y_fit_movery = addLines(cnt_movery, y)
    plt.plot(y_fit_ours, x_fit_ours, marker='o', markersize=6, label=r"$\textsc{vmud}$",
             color=constants.line_color_rq1[0])
    plt.plot(y_fit_vuddy, x_fit_vuddy, marker='*', markersize=6, label=r"$\textsc{vuddy}$",
             color=constants.line_color_rq1[1])
    plt.plot(y_fit_MVP, x_fit_MVP, marker='+', markersize=6, label=r"$\textsc{mvp}$", color=constants.line_color_rq1[2])
    plt.plot(y_fit_v1scan, x_fit_v1scan, marker='^', markersize=6, label=r"$\textsc{v1scan}$",
             color=constants.line_color_rq1[3])
    plt.ylabel('Number of Repositories (\#)', fontsize=14, fontfamily=FontSizeAll.FONT_FAMILY)
    plt.xlabel('F1-Score', fontsize=14, fontfamily=FontSizeAll.FONT_FAMILY)
    plt.legend(loc='lower left', fontsize=12)
    plt.grid(True)
    plt.savefig('./figs/rq1_repocdf_f1score.pdf',
                format='pdf', bbox_inches='tight')


def drawCDFPrec():
    plt.figure()
    discardRepo = getDiscardRepo()
    rec_ours, prec_ours, f1score_ours = getrepoResults("./results/results_repo_vmud.json", discardRepo)
    rec_movery, prec_movery, f1score_movery = getrepoResults("./results/results_repo_movery.json", discardRepo)
    rec_v1scan, prec_v1scan, f1score_v1scan = getrepoResults("./results/results_repo_v1scan.json", discardRepo)
    rec_MVP, prec_MVP, f1score_MVP = getrepoResults("./results/results_repo_MVP.json", discardRepo)
    rec_vuddy, prec_vuddy, f1score_vuddy = getrepoResults("./results/results_repo_vuddy.json", discardRepo)
    cnt_ours = getNum(prec_ours)
    cnt_movery = getNum(prec_movery)
    cnt_v1scan = getNum(prec_v1scan)
    cnt_MVP = getNum(prec_MVP)
    cnt_vuddy = getNum(prec_vuddy)
    # print(cnt_vuddy, cnt_MVP, cnt_v1scan, cnt_movery, cnt_ours)
    y = np.arange(0, 1.1, 0.1)
    # x_fit_ours, y_fit_ours = myPoly(cnt_ours, y)
    # x_fit_vuddy, y_fit_vuddy = myPoly(cnt_vuddy, y)
    # x_fit_MVP, y_fit_MVP = myPoly(cnt_MVP, y)
    # x_fit_v1scan, y_fit_v1scan = myPoly(cnt_v1scan, y)
    # x_fit_movery, y_fit_movery = myPoly(cnt_movery, y)
    x_fit_ours, y_fit_ours = addLines(cnt_ours, y)
    x_fit_vuddy, y_fit_vuddy = addLines(cnt_vuddy, y)
    x_fit_MVP, y_fit_MVP = addLines(cnt_MVP, y)
    x_fit_v1scan, y_fit_v1scan = addLines(cnt_v1scan, y)
    x_fit_movery, y_fit_movery = addLines(cnt_movery, y)
    plt.plot(y_fit_ours, x_fit_ours, marker='o', markersize=6, label=r"$\textsc{vmud}$",
             color=constants.line_color_rq1[0])
    plt.plot(y_fit_vuddy, x_fit_vuddy, marker='*', markersize=6, label=r"$\textsc{vuddy}$",
             color=constants.line_color_rq1[1])
    plt.plot(y_fit_MVP, x_fit_MVP, marker='+', markersize=6, label=r"$\textsc{mvp}$", color=constants.line_color_rq1[2])
    plt.plot(y_fit_v1scan, x_fit_v1scan, marker='^', markersize=6, label=r"$\textsc{v1scan}$",
             color=constants.line_color_rq1[3])
    # plt.plot(x_fit_movery, y_fit_movery, marker='s', markersize=6, label=r"$\textsc{movery}$",
    #          color=constants.line_color_rq1[4])
    plt.ylabel('Number of Repositories (\#)', fontsize=14, fontfamily=FontSizeAll.FONT_FAMILY)
    plt.xlabel('Precision', fontsize=14, fontfamily=FontSizeAll.FONT_FAMILY)
    plt.legend(loc='lower left', fontsize=12)
    plt.grid(True)
    # plt.show()
    plt.savefig('./figs/rq1_repocdf_prec.pdf',
                format='pdf', bbox_inches='tight')


def drawCDFRec():
    plt.figure()
    discardRepo = getDiscardRepo()
    rec_ours, prec_ours, f1score_ours = getrepoResults("./results/results_repo_vmud.json", discardRepo)
    rec_movery, prec_movery, f1score_movery = getrepoResults("./results/results_repo_movery.json", discardRepo)
    rec_v1scan, prec_v1scan, f1score_v1scan = getrepoResults("./results/results_repo_v1scan.json", discardRepo)
    rec_MVP, prec_MVP, f1score_MVP = getrepoResults("./results/results_repo_MVP.json", discardRepo)
    rec_vuddy, prec_vuddy, f1score_vuddy = getrepoResults("./results/results_repo_vuddy.json", discardRepo)
    cnt_ours = getNum(rec_ours)
    # cnt_movery = getNum(rec_movery)
    cnt_v1scan = getNum(rec_v1scan)
    cnt_MVP = getNum(rec_MVP)
    cnt_vuddy = getNum(rec_vuddy)
    print(cnt_vuddy)
    # print(len(rec_ours))
    y = np.arange(0, 1.1, 0.1)
    # x_fit_ours, y_fit_ours = myPoly(cnt_ours, y)
    # x_fit_vuddy, y_fit_vuddy = myPoly(cnt_vuddy, y)
    # x_fit_MVP, y_fit_MVP = myPoly(cnt_MVP, y)
    # x_fit_v1scan, y_fit_v1scan = myPoly(cnt_v1scan, y)
    # x_fit_movery, y_fit_movery = myPoly(cnt_movery, y)
    x_fit_ours, y_fit_ours = addLines(cnt_ours, y)
    x_fit_vuddy, y_fit_vuddy = addLines(cnt_vuddy, y)
    x_fit_MVP, y_fit_MVP = addLines(cnt_MVP, y)
    x_fit_v1scan, y_fit_v1scan = addLines(cnt_v1scan, y)
    # x_fit_movery, y_fit_movery = addLines(cnt_movery, y)
    # plt.plot(cnt_ours, y, 'o', color=constants.line_color_rq1[0])
    # plt.plot(cnt_movery, y, '*', color=constants.line_color_rq1[4])
    # plt.plot(cnt_v1scan, y, '+', color=constants.line_color_rq1[3])
    # plt.plot(cnt_MVP, y, '^', color=constants.line_color_rq1[2])
    # plt.plot(cnt_vuddy, y, 's', color=constants.line_color_rq1[1])
    plt.plot(y_fit_ours, x_fit_ours, marker='o', markersize=6, label=r"$\textsc{vmud}$",
             color=constants.line_color_rq1[0])
    plt.plot(y_fit_vuddy, x_fit_vuddy, marker='*', markersize=6, label=r"$\textsc{vuddy}$",
             color=constants.line_color_rq1[1])
    plt.plot(y_fit_MVP, x_fit_MVP, marker='+', markersize=6, label=r"$\textsc{mvp}$", color=constants.line_color_rq1[2])
    plt.plot(y_fit_v1scan, x_fit_v1scan, marker='^', markersize=6, label=r"$\textsc{v1scan}$",
             color=constants.line_color_rq1[3])
    # plt.plot(x_fit_movery, y_fit_movery, marker='s', markersize=6, label=r"$\textsc{movery}$",
    #          color=constants.line_color_rq1[4])
    plt.ylabel('Number of Repositories (\#)', fontsize=14, fontfamily=FontSizeAll.FONT_FAMILY)
    plt.xlabel('Recall', fontsize=14, fontfamily=FontSizeAll.FONT_FAMILY)
    plt.legend(loc='lower left', fontsize=12)
    plt.grid(True)
    plt.savefig('./figs/rq1_repocdf_rec.pdf',
                format='pdf', bbox_inches='tight')
    # plt.show()




if __name__ == "__main__":
    # drawScatter()
    drawCDFPrec()
    drawCDFRec()
    drawCDFf1score()
