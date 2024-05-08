import matplotlib.pyplot as plt
import numpy as np
import json
from typing import List, Tuple, Any

import FontSizeAll
import constants


def getrepoInfo(fileName):
    nums = []
    with open(fileName, "r") as f:
        repoInfo = json.load(f)
        for repo in repoInfo.keys():
            nums.append(float(repoInfo[repo]))
    return nums


def compute_box_stats(box) -> Tuple[Any, Any, Any, Any, Any]:
    lower_extreme = box['whiskers'][0].get_xdata()[1]
    lower_quartile = box['whiskers'][0].get_xdata()[0]
    med = box['medians'][0].get_xdata()[0]
    upper_quartile = box['whiskers'][1].get_xdata()[0]
    upper_extreme = box['whiskers'][1].get_xdata()[1]

    return lower_extreme, lower_quartile, med, upper_quartile, upper_extreme


def drawBox():
    fileNums = getrepoInfo("./data/repoFileNum.json")
    codeNums = getrepoInfo("./data/repoCodeNum.json")
    repoInfo = [fileNums, codeNums]
    plt.rcParams["font.family"] = "Times New Roman"
    plt.rcParams['axes.unicode_minus'] = False
    plt.rcParams['axes.linewidth'] = 0.3
    tittleName = ["Files", "Code(LOC)"]
    fig, axs = plt.subplots(2, 1, figsize=(15, 6))
    np.random.seed(213)
    flag = False
    # plt.boxplot(repoInfo[0],showfliers=False, vert=False)
    for i, ax in enumerate(axs):
        # ax.set_title(f'repo \'s Number of {tittleName[i]}')
        medianprops = dict(linewidth=1.0, color='black')
        box = ax.boxplot(repoInfo[i], sym='+', showfliers=False,
                         medianprops=medianprops, vert=False,  widths=0.3)
        # ax.set_ylabel('num')
    #
        rotation = 0
        # ax.set_xticklabels("repos", fontsize=14,
        #                    family='Times New Roman', rotation=rotation, va='center')
        ax.set_xlabel(f"Lines of {tittleName[i]} (#)", fontsize=26, fontname='Times New Roman')
        y = compute_box_stats(box)    # ax.set_xlim(0, 6200)
    #     ax.set_ylim(0.8, 1.2)
        label_y = [i if i < 1000 else '%.1fK' % (i / 1000) for i in y]
        print(y)
        print(label_y)
        y = np.array(y)
        print(y.min())
        if y.min() == 1:
            ax.set_xlim(y.min() - 50, y.max() + 300)
            outlier = np.random.uniform(600, 800, 5)
            y = np.append(y, 750)
            label_y.append("30K")
            flag = True
        else:
            ax.set_xlim(y.min() - 50000, y.max() + 100000)
            outlier = np.random.uniform(300000, 337624, 5)
            y = np.append(y, 300000)
            label_y.append("10M")
            flag = False
    #
        x_dot = [1] * 5
        ax.scatter(outlier,x_dot, marker="+", color="black")
        y = [-10000 if i == 5 else i for i in y]
        y = [23300 if i == 20888.0 else i for i in y]
        y = [-12 if i == 1 else i for i in y]
        ax.set_xticks(y)
        y = [5 if i == -10000 else i for i in y]
        y = [1 if i == -12 else i for i in y]
        y = [20888.0 if i == 23300 else i for i in y]
        ax.set_xticklabels(label_y, family='Times New Roman', size=19, rotation=0)
        # ax.set_xticklabels(["repos"], fontsize=14,family='Times New Roman', rotation=rotation, va='center')
        # ax.tick_params(axis='x', which='major', pad=10)
        TICK_THICK = 1.0
        TICK_LENGTH = 1.5
        ax.xaxis.set_tick_params(
            width=TICK_THICK, length=TICK_LENGTH, direction='in')
        # ax.xaxis.set_tick_params(
        #     width=TICK_THICK, length=TICK_LENGTH, direction='in')
        if flag:
            # print(1222222)
            ax.text(650,0.45, "...", fontsize=19, ha='center', va='center')
        else:
            ax.text(270000, 0.45, "...", fontsize=19, ha='center', va='center')
        ax.get_yaxis().set_visible(False)
    # plt.show()
    plt.subplots_adjust(hspace=0.5)
    plt.savefig('./figs/rq0_repoInfo.pdf',
                format='pdf', bbox_inches='tight')

if __name__ == "__main__":
    drawBox()
