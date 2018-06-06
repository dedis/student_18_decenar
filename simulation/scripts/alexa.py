#!/usr/bin/python3

import pandas as pd
import sys
import matplotlib.pyplot as plt
import numpy as np

# main
if len(sys.argv) != 2:
    print("Usage: " + sys.argv[0] + " csvFile")
    sys.exit()

data = np.loadtxt(sys.argv[1])
sorted_data = np.sort(data)
yvals=np.arange(len(sorted_data))/float(len(sorted_data))
plt.plot(sorted_data,yvals)

xlabel_name = "Number of unique leaves"
ylabel_name = "Cumulative probability"
output_name = "leaves.pdf"

plt.gca().yaxis.grid(True, linestyle='--')
plt.gca().xaxis.grid(True, linestyle='--')
plt.yticks([0.2, 0.4, 0.6, 0.8, 0.96, 1.0])
plt.xticks([0, 512, 1000, 2000, 3000, 4000, 5000])
plt.ylabel(ylabel_name, size=12)
plt.xlabel(xlabel_name, size=12)

plt.tight_layout()
plt.savefig("/home/yabasta/scuola/pdm/report/images/leaves_cdf.pdf", format="pdf")
