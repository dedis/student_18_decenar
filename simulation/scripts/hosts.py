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

# colors
palette = ['#4D4D4D', '#5DA5DA',  '#FAA43A', '#60BD68',  '#F17CB0']

# x axis
#x_values = [3, 5, 10, 15, 20]
x_values = [7, 16, 32, 64]

# data
consensus = data.loc[:, "consensus_structured_wall_avg"]
decrypt = data.loc[:, "decrypt_wall_avg"]
reconstruct = data.loc[:, "reconstruct_wall_avg"]
sign = data.loc[:, "sign_wall_avg"]
complete = data.loc[:, "Complete round_wall_avg"]

# interpolation

width = 0.15
n = len(x_values)
ind = np.arange(n)

xlabel_name = "Number of hosts"
ylabel_name = "Time [s]"
output_name = "hosts.pdf"

fig, ax = plt.subplots()
ax.bar(ind, consensus, width, color=palette[0], label='Consensus structured')
ax.bar(ind + width, decrypt, width, color=palette[1], label='Decrypt')
ax.bar(ind + 2*width, reconstruct, width, color=palette[2], label='Reconstruct')
ax.bar(ind + 3*width, sign, width, color=palette[3], label='Signature')
ax.plot(ind + 3/2*width, complete, color = 'black', label='Total', marker='.')
for a, b in zip(ind + 3/2*width, complete):
    ax.annotate(str(int(b)), xy=(a, b), xytext=(-15, 4), textcoords='offset points')

ax.set_xticks(ind + width*3/2)
ax.set_xticklabels(x_values)
plt.ylabel(ylabel_name, size=12)
plt.xlabel(xlabel_name, size=12)
plt.tick_params('y', labelsize=12)
plt.gca().yaxis.grid(True, linestyle='--')
plt.ylabel(ylabel_name, size=12)
plt.xlabel(xlabel_name, size=12)
plt.tick_params('y', labelsize=12)
plt.gca().yaxis.grid(True, linestyle='--')

plt.yscale('log')
plt.tight_layout()
plt.legend(loc="upper left", prop={'size': 12})
plt.savefig("/home/yabasta/scuola/pdm/report/images/" + output_name, format="pdf")
#plt.savefig(output_name, format="pdf")

#print_all(len(source_names), source_names, data_a_means, data_a_stds, data_b_means, data_b_stds)
