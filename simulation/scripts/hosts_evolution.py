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
x_values = [3, 5, 10, 15, 20]

color = ['#4D4D4D', '#5DA5DA',  '#FAA43A', '#60BD68',  '#F17CB0', '#B2912F']

# data
consensus = data.loc[:, "consensus_structured_wall_avg"]
decrypt = data.loc[:, "decrypt_wall_avg"]
reconstruct = data.loc[:, "reconstruct_wall_avg"]
sign = data.loc[:, "sign_wall_avg"]
complete = data.loc[:, "Complete round_wall_avg"]

# interpolation

ind = [x for x, _ in enumerate(x_values)]

xlabel_name = "Number of hosts"
ylabel_name = "Time [s]"
output_name = "hosts_evolution.pdf"

plt.ylabel(ylabel_name, size=12)
plt.xlabel(xlabel_name, size=12)
plt.tick_params('y', labelsize=12)
plt.xticks(ind, x_values, size=12)
plt.gca().yaxis.grid(True, linestyle='--')

plt.plot(ind, consensus, color=color[0], label='Consensus structured')
plt.plot(ind, decrypt, color=color[1], label='Decrypt') 
plt.plot(ind, reconstruct, color=color[2], label='Reconstruct')
plt.plot(ind, sign, color=color[3], label='Signature')
plt.plot(ind, consensus + decrypt + sign + consensus, color=color[4], label='Total')
#plt.plot(ind, [0.65*(i ** 1.025) for i in x_values], color='black', label='Empirical bound', linestyle=':')

plt.yscale('log')
#plt.legend(loc="upper left", prop={'size': 12})
plt.legend(bbox_to_anchor=(0., 1.02, 1., .102), loc=3,
        ncol=2, mode="expand", borderaxespad=0., prop={'size': 12})
plt.tight_layout()
plt.savefig("/home/yabasta/scuola/pdm/report/images/" + output_name, format="pdf")
#plt.savefig(output_name, format="pdf")
#print_all(len(source_names), source_names, data_a_means, data_a_stds, data_b_means, datab_stds)
