#!/usr/bin/python3

import pandas as pd
import sys
import matplotlib.pyplot as plt
import numpy as np

def get_data(filename):
    return pd.read_csv(filename)
    
# main
if len(sys.argv) != 2:
    print("Usage: " + sys.argv[0] + " csvFile")
    sys.exit()

# this should go into get data
data = get_data(sys.argv[1])

# x axis
x_values = [i for i in range(1, 8)]

# data
consensus = data.loc[:, "consensus_structured_wall_avg"]/60
decrypt = data.loc[:, "decrypt_wall_avg"]/60
reconstruct = data.loc[:, "reconstruct_wall_avg"]/60
sign = data.loc[:, "sign_wall_avg"]/60
additional = data.loc[:, "additional_data_wall_avg"]/60
complete = data.loc[:, "Complete round_wall_avg"]/60

palette = ['#4D4D4D', '#5DA5DA',  '#FAA43A', '#60BD68',  '#F17CB0']

width = 0.15
n = len(x_values)
ind = np.arange(n)

xlabel_name = "Webpage ID"
ylabel_name = "Time [m]"
output_name = "real.pdf"

fig, ax = plt.subplots()
ax.bar(ind, consensus, width, color=palette[0], label='Consensus structured')
ax.bar(ind + width, decrypt, width, color=palette[1], label='Decrypt')
ax.bar(ind + 2*width, reconstruct, width, color=palette[2], label='Reconstruct')
ax.bar(ind + 3*width, sign, width, color=palette[3], label='Signature')
ax.bar(ind + 4*width, additional, width, color=palette[4], label='Additional')
ax.set_xticks(ind + width*2)
ax.set_xticklabels(x_values)
plt.ylabel(ylabel_name, size=12)
plt.xlabel(xlabel_name, size=12)
plt.tick_params('y', labelsize=12)
plt.gca().yaxis.grid(True, linestyle='--')

total = consensus + decrypt + reconstruct + sign + additional
mean = total.mean()

plt.axhline(mean, color='#B2912F', linewidth=2, label='Mean')

plt.yscale('log')

plt.legend(bbox_to_anchor=(0., 1.02, 1., .102), loc=3,
        ncol=2, mode="expand", borderaxespad=0., prop={'size': 12})
plt.tight_layout()
plt.savefig("/home/yabasta/scuola/pdm/report/images/" + output_name, format="pdf")

#print_all(len(source_names), source_names, data_a_means, data_a_stds, data_b_means, data_b_stds)
