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


def getrepoResults(fileName):
    rec = []
    prec = []
    f1score = []
    with open(fileName, "r") as f:
        repoAccuracy = json.load(f)
        for t in repoAccuracy.keys():
            rec.append(repoAccuracy[t]["recall"])
            prec.append(repoAccuracy[t]["precision"])
            f1score.append(repoAccuracy[t]["F1score"])
    # print(discard)
    return rec, prec, f1score


def drawlines_th1():
    plt.figure()
    rec_ours, prec_ours, f1score_ours = getrepoResults("./datas/param_th_pr.json")
    x = np.arange(0, 1, 0.001)
    max = 0
    maxi = 0
    for i in range(0, 1000):
        if f1score_ours[i] > max:
            max = f1score_ours[i]
            maxi = i
    plt.xlim(0, 1.0)
    plt.ylim(0.5, 1.0)
    plt.plot([maxi / 1000, 0], [max, max], color=constants.line_color_rq1[0], linestyle='--')
    plt.plot([maxi / 1000, maxi / 1000], [max, 0], color=constants.line_color_rq1[0], linestyle='--')
    plt.text(0.1, 0.9, f"({'%.3f' % (maxi / 1000)},{'%.2f' % max})", fontsize=14, ha='center', va='center')
    plt.plot(x, prec_ours, label="Precision", color=constants.line_color_rq1[4])
    plt.plot(x, rec_ours, label="Recall", color=constants.line_color_rq1[1])
    plt.plot(x, f1score_ours, label="F1-Score", color=constants.line_color_rq1[2])
    plt.legend()
    plt.grid(True)

    # print(maxi)
    plt.savefig('./figs/rq4_th_pr.pdf',
                format='pdf', bbox_inches='tight')


def drawlines_th2():
    plt.figure()
    rec_ours, prec_ours, f1score_ours = getrepoResults("./datas/param_th_syn_v.json")
    x = np.arange(0.1, 1.1, 0.1)
    max = 0
    maxi = 0
    for i in range(0, 10):
        if f1score_ours[i] > max:
            max = f1score_ours[i]
            maxi = i
    plt.xlim(0.1, 1.0)
    plt.ylim(0.5, 1.0)
    plt.plot([(maxi+1) / 10, 0], [max, max], color=constants.line_color_rq1[0], linestyle='--')
    plt.plot([(maxi+1) / 10, (maxi+1) / 10], [max, 0], color=constants.line_color_rq1[0], linestyle='--')
    plt.text(0.6, 0.78, f"({'%.1f' % ((maxi+1) / 10)},{'%.2f' % max})", fontsize=14, ha='center', va='center')
    plt.plot(x, prec_ours, label="Precision", marker='o', markersize=6, color=constants.line_color_rq1[4])
    plt.plot(x, rec_ours, label="Recall", marker='+', markersize=6, color=constants.line_color_rq1[1])
    plt.plot(x, f1score_ours, label="F1-Score", marker='*', markersize=6, color=constants.line_color_rq1[2])
    plt.legend()
    plt.grid(True)

    print(maxi,max)
    plt.savefig('./figs/rq4_th_syn_v.pdf',
                format='pdf', bbox_inches='tight')

def drawlines_th3():
    plt.figure()
    rec_ours, prec_ours, f1score_ours = getrepoResults("./datas/param_th_sem_v.json")
    x = np.arange(0.1, 1.1, 0.1)
    max = 0
    maxi = 0
    for i in range(0, 10):
        if f1score_ours[i] > max:
            max = f1score_ours[i]
            maxi = i
    plt.xlim(0.1, 1.0)
    plt.ylim(0.5, 1.0)
    plt.plot([(maxi+1) / 10, 0], [max, max], color=constants.line_color_rq1[0], linestyle='--')
    plt.plot([(maxi+1) / 10, (maxi+1) / 10], [max, 0], color=constants.line_color_rq1[0], linestyle='--')
    plt.text(0.5, 0.78, f"({'%.1f' % ((maxi+1) / 10)},{'%.2f' % max})", fontsize=14, ha='center', va='center')
    plt.plot(x, prec_ours, label="Precision", marker='o', markersize=6, color=constants.line_color_rq1[4])
    plt.plot(x, rec_ours, label="Recall", marker='+', markersize=6, color=constants.line_color_rq1[1])
    plt.plot(x, f1score_ours, label="F1-Score", marker='*', markersize=6, color=constants.line_color_rq1[2])
    plt.legend()
    plt.grid(True)

    print(maxi,max)
    plt.savefig('./figs/rq4_th_sem_v.pdf',
                format='pdf', bbox_inches='tight')

def drawlines_th4():
    plt.figure()
    rec_ours, prec_ours, f1score_ours = getrepoResults("./datas/param_th_syn_p.json")
    x = np.arange(0.1, 1.1, 0.1)
    max = 0
    maxi = 0
    for i in range(0, 10):
        if f1score_ours[i] >= max:
            max = f1score_ours[i]
            maxi = i
    plt.xlim(0.1, 1.0)
    plt.ylim(0.5, 1.0)
    plt.plot([(maxi+1) / 10, 0], [max, max], color=constants.line_color_rq1[0], linestyle='--')
    plt.plot([(maxi+1) / 10, (maxi+1) / 10], [max, 0], color=constants.line_color_rq1[0], linestyle='--')
    plt.text(0.4, 0.86, f"({'%.1f' % ((maxi+1) / 10)},{'%.2f' % max})", fontsize=14, ha='center', va='center')
    plt.plot(x, prec_ours, label="Precision", marker='o', markersize=6, color=constants.line_color_rq1[4])
    plt.plot(x, rec_ours, label="Recall", marker='+', markersize=6, color=constants.line_color_rq1[1])
    plt.plot(x, f1score_ours, label="F1-Score", marker='*', markersize=6, color=constants.line_color_rq1[2])
    plt.legend()
    plt.grid(True)

    print(maxi,max)
    plt.savefig('./figs/rq4_th_syn_p.pdf',
                format='pdf', bbox_inches='tight')

def drawlines_th5():
    plt.figure()
    rec_ours, prec_ours, f1score_ours = getrepoResults("./datas/param_th_sem_p.json")
    x = np.arange(0.1, 1.1, 0.1)
    max = 0
    maxi = 0
    for i in range(0, 10):
        if f1score_ours[i] >= max:
            max = f1score_ours[i]
            maxi = i
    plt.xlim(0.1, 1.0)
    plt.ylim(0.5, 1.0)
    plt.plot([(maxi+1) / 10, 0], [max, max], color=constants.line_color_rq1[0], linestyle='--')
    plt.plot([(maxi+1) / 10, (maxi+1) / 10], [max, 0], color=constants.line_color_rq1[0], linestyle='--')
    plt.text(0.5, 0.86, f"({'%.1f' % ((maxi+1) / 10)},{'%.2f' % max})", fontsize=14, ha='center', va='center')
    plt.plot(x, prec_ours, label="Precision", marker='o', markersize=6, color=constants.line_color_rq1[4])
    plt.plot(x, rec_ours, label="Recall", marker='+', markersize=6, color=constants.line_color_rq1[1])
    plt.plot(x, f1score_ours, label="F1-Score", marker='*', markersize=6, color=constants.line_color_rq1[2])
    plt.legend()
    plt.grid(True)

    print(maxi,max)
    plt.savefig('./figs/rq4_th_sem_p.pdf',
                format='pdf', bbox_inches='tight')

def drawlines_th6():
    plt.figure()
    rec_ours, prec_ours, f1score_ours = getrepoResults("./datas/param_th_ce.json")
    x = np.arange(0.1, 1.1, 0.1)
    max = 0
    maxi = 0
    for i in range(0, 10):
        if f1score_ours[i] >= max:
            max = f1score_ours[i]
            maxi = i
    plt.xlim(0.1, 1.0)
    plt.ylim(0.5, 1.0)
    plt.plot([(maxi+1) / 10, 0], [max, max], color=constants.line_color_rq1[0], linestyle='--')
    plt.plot([(maxi+1) / 10, (maxi+1) / 10], [max, 0], color=constants.line_color_rq1[0], linestyle='--')
    plt.text(0.7, 0.86, f"({'%.1f' % ((maxi+1) / 10)},{'%.2f' % max})", fontsize=14, ha='center', va='center')
    plt.plot(x, prec_ours, label="Precision", marker='o', markersize=6, color=constants.line_color_rq1[4])
    plt.plot(x, rec_ours, label="Recall", marker='+', markersize=6, color=constants.line_color_rq1[1])
    plt.plot(x, f1score_ours, label="F1-Score", marker='*', markersize=6, color=constants.line_color_rq1[2])
    plt.legend()
    plt.grid(True)

    print(maxi,max)
    plt.savefig('./figs/rq4_th_ce.pdf',
                format='pdf', bbox_inches='tight')


if __name__ == "__main__":
    drawlines_th1()
    drawlines_th2()
    drawlines_th3()
    drawlines_th4()
    drawlines_th5()
    drawlines_th6()
