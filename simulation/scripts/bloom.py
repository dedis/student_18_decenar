#!/usr/bin/python3

import pandas as pd
import sys
import matplotlib.pyplot as plt
import numpy as np

# x axis
x_values = [64, 128, 256, 512, 1024, 2048]

# data
ind = [x for x, _ in enumerate(x_values)]


xlabel_name = "Number of leaves"
ylabel_name = "Bloom filter size"
output_name = "bloom.pdf"

plt.ylabel(ylabel_name, size=12)
plt.xlabel(xlabel_name, size=12)
plt.tick_params('y', labelsize=12)
plt.xticks(ind, x_values, size=12)
plt.gca().yaxis.grid(True, linestyle='--')

plt.plot(ind, [614, 1227, 2454, 4908, 9816, 19631], '-', color ='black', label='Bloom filter size')

plt.yscale('log')

plt.tight_layout()
plt.legend(loc="upper left", prop={'size': 12})
plt.savefig("/home/yabasta/scuola/pdm/report/images/" + output_name, format="pdf")
#plt.savefig(output_name, format="pdf")

#print_all(len(source_names), source_names, data_a_means, data_a_stds, data_b_means, data_b_stds)
