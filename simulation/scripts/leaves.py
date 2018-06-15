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
consensus = data.loc[:, "consensus_structured_wall_avg"]
decrypt = data.loc[:, "decrypt_wall_avg"]
reconstruct = data.loc[:, "reconstruct_wall_avg"]
sign = data.loc[:, "sign_wall_avg"]
complete = data.loc[:, "complete_round_wall_avg"]

palette = ['#4D4D4D', '#5DA5DA',  '#FAA43A', '#60BD68',  '#F17CB0']

width = 0.15
n = len(x_values)
ind = np.arange(n)


xlabel_name = "Number of leaves"
ylabel_name = "Time [s]"
output_name = "leaves.pdf"

fig, ax = plt.subplots()
ax.bar(ind, consensus, width, color=palette[0], label='Consensus structured')
ax.bar(ind + width, decrypt, width, color=palette[1], label='Decrypt')
ax.bar(ind + 2*width, reconstruct, width, color=palette[2], label='Reconstruct')
ax.bar(ind + 3*width, sign, width, color=palette[3], label='Signature')
ax.plot(ind + 3/2*width, consensus+decrypt+reconstruct+sign, color = 'black', label='Total')
ax.set_xticks(ind + width * 3/2)
ax.set_xticklabels(x_values)

plt.ylabel(ylabel_name, size=12)
plt.xlabel(xlabel_name, size=12)
plt.tick_params('y', labelsize=12)
plt.yscale('log')
plt.gca().yaxis.grid(True, linestyle='--')
plt.tight_layout()
plt.legend(loc="upper left", prop={'size': 12})
plt.savefig("/home/yabasta/scuola/pdm/report/images/" + output_name, format="pdf")

#print_all(len(source_names), source_names, data_a_means, data_a_stds, data_b_means, data_b_stds)
