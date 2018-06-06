import matplotlib.pyplot as plt 
import pandas as pd
import sys
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

color = ['#4D4D4D', '#5DA5DA',  '#FAA43A', '#60BD68',  '#F17CB0']

fig = plt.figure()
host = fig.add_subplot(111)

par1 = host.twinx()

host.set_xlabel("Number of leaves")
host.set_ylabel("Time[s]")
par1.set_ylabel("Bloom filter size")

consensus = data.loc[:, "consensus_structured_wall_avg"]
decrypt = data.loc[:, "decrypt_wall_avg"]
reconstruct = data.loc[:, "reconstruct_wall_avg"]
sign = data.loc[:, "sign_wall_avg"]/60
complete = data.loc[:, "complete_round_wall_avg"]

# interpolation

ind = [x for x, _ in enumerate(x_values)]


p1, = host.plot(ind, consensus, color=color[0], label='Consensus structured')
p2, = host.plot(ind, decrypt, color=color[1], label='Decrypt') 
p3, = host.plot(ind, reconstruct, color=color[2], label='Reconstruct')
p4, = host.plot(ind, sign, color=color[3], label='Signature')
p4, = par1.plot(ind, [10*614, 100*1227, 1000*2454, 10000*4908, 100000*9816, 1000000*19631], '-', color ='black', label='Bloom filter size')

host.set_yscale('log')
host.set_xticks(ind, x_values)

host_ticks = host.get_yticks()
par1_scale = host_ticks
#par1.set_yticks(np.linspace(par1.get_yticks()[0], par1.get_yticks()[-1], len(host.get_yticks())))
par1.set_yscale('log')
par1.set_yticks(par1_scale)
#par1.set_ylim([ymin, 70000])

lns = [p1, p2, p3, p4]
host.legend(handles=lns, loc='best')

# Sometimes handy, same for xaxis
#par2.yaxis.set_ticks_position('right')

host.yaxis.label.set_color('black')
par1.yaxis.label.set_color('black')

plt.show()
