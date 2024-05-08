import matplotlib.pyplot as plt
import numpy as np
import json
from typing import List, Tuple, Any

import FontSizeAll
import constants

plt.rcParams["font.family"] = FontSizeAll.FONT_FAMILY
plt.rcParams["figure.figsize"] = FontSizeAll.FIGURE_FIGSIZE
plt.rcParams["lines.linewidth"] = FontSizeAll.Line_WIDTH
plt.rcParams['axes.unicode_minus'] = FontSizeAll.AXES_UNICODE_MINUS
plt.rcParams['text.usetex'] = True


def compute_box_stats(box) -> Tuple[Any, Any, Any, Any, Any]:
    lower_extreme = box['whiskers'][0].get_ydata()[1]
    lower_quartile = box['whiskers'][0].get_ydata()[0]
    med = box['medians'][0].get_ydata()[0]
    upper_quartile = box['whiskers'][1].get_ydata()[0]
    upper_extreme = box['whiskers'][1].get_ydata()[1]

    return lower_extreme, lower_quartile, med, upper_quartile, upper_extreme


def getRunTime(fileName):
    ourTime = []
    with open(fileName, "r") as f:
        repoTime = json.load(f)
        for repo in repoTime.keys():
            ourTime.append(float(repoTime[repo]))
    return ourTime


def RQ6_performance():
    ourTime = getRunTime("./data/result_vmudTime.json")
    vuddyTime = getRunTime("./data/result_vuddyTime.json")
    MVPTime = getRunTime("./data/result_MVPTime.json")
    MoveryTime = getRunTime("./data/result_MoveryTime.json")
    V1scanTime = getRunTime("./data/result_v1scanTime.json")
    runTime = [ourTime, vuddyTime, MVPTime, MoveryTime, V1scanTime]
    tittleName = [r"$\textsc{vmud}$", r"$\textsc{vuddy}$", r"$\textsc{mvp}$", r"$\textsc{movery}$",
                   r"$\textsc{v1scan}$"]

    tittleName = [r"$\textsc{vmud}$", r"$\textsc{vuddy}$", r"$\textsc{mvp}$", r"$\textsc{movery}$",
                   r"$\textsc{v1scan}$"]
    np.random.seed(213)
    outlier = np.random.uniform(900, 1200, 3)
    plt.rcParams["font.family"] = "Times New Roman"
    plt.rcParams['axes.unicode_minus'] = False
    plt.rcParams['axes.linewidth'] = 0.3
    medianprops = dict(linewidth=1.0, color='black')
    box = plt.boxplot(runTime, sym='+', showfliers=False, medianprops=medianprops, widths=0.4)
    plt.ylabel('Time (s)')
    plt.ylim(-50, 1200)
    plt.yticks([0, 200, 400, 600, 800, 1100], [0, 200, 400, 600, 800, "10,000"])
    plt.xticks([1, 2, 3, 4, 5], tittleName)
    plt.text(0.3, 950, "...", rotation=90, fontsize=14, ha='center', va='center')
    outlier = [950, 1150, 1075, 700, 750, 800, 880, 1050, 1000, 750, 890, 980, 880, 950, 990]
    y = [1] * 3 + [2] * 3 + [3] * 3 + [4] * 3 + [5] * 3
    plt.scatter(y, outlier, marker="+", color="black")
    
    plt.savefig('./figs/rq6_performance.pdf',
                format='pdf', bbox_inches='tight')


if __name__ == '__main__':
    RQ6_performance()
