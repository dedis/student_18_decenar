#!/usr/bin/python3

import pandas as pd
import sys
import matplotlib.pyplot as plt
import numpy as np

def get_data(filename):
    return pd.read_csv(filename)
    

# Attach a label above each bar displaying its height
def show_bar_value(rects):
    for rect in rects:
        height = rect.get_height()
        ax.text(rect.get_x() + rect.get_width() / 2., 1.05 * height,
                '%d' % int(height),
                ha='center', va='bottom')

# main
if len(sys.argv) != 2:
    print("Usage: " + sys.argv[0] + " csvFile")
    sys.exit()

# this should go into get data
data = get_data(sys.argv[1])

# x axis
x_values = [64, 128, 256, 512, 1024, 2048]

# data
consensus = data.loc[:, "Consensus structured_wall_avg"]
decrypt = data.loc[:, "Decrypt_wall_avg"]
reconstruct = data.loc[:, "Reconstruct_wall_avg"]
sign = data.loc[:, "Sign_wall_avg"]
complete = data.loc[:, "Complete round_wall_avg"]

# interpolation

width = 0.35
ind = [x for x, _ in enumerate(x_values)]


xlabel_name = "Number of leaves"
ylabel_name = "Time [s]"
output_name = "leaves.pdf"

plt.ylabel(ylabel_name, size=12)
plt.xlabel(xlabel_name, size=12)
plt.tick_params('y', labelsize=12)
plt.xticks(ind, x_values, size=12)
plt.gca().yaxis.grid(True, linestyle='--')

plt.bar(ind, consensus, width, color='orange', label='Consensus structured')
plt.bar(ind, decrypt, width, color='lightblue', label='Decrypt', bottom=consensus)
plt.bar(ind, reconstruct, width, color='lightgreen', label='Reconstruct', bottom=consensus+decrypt)
plt.bar(ind, sign, width, color='red', label='Signature', bottom=consensus+decrypt+reconstruct)
plt.plot(ind, consensus + decrypt + reconstruct + sign, '.-', color ='black')

plt.tight_layout()
plt.legend(loc="upper left", prop={'size': 12})
plt.savefig("/home/yabasta/scuola/pdm/report/images/" + output_name, format="pdf")
#plt.savefig(output_name, format="pdf")

#print_all(len(source_names), source_names, data_a_means, data_a_stds, data_b_means, data_b_stds)
