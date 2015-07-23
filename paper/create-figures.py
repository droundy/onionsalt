#!/usr/bin/python3

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

plt.figure(figsize=(8,3))

delt = 0.2

def rectangle(x1, x2, y1, y2, name, color = 'k'):
    x1 = x1+delt
    x2 = x2-delt
    plt.plot([x1, x1, x2, x2, x1], [y1, y2, y2, y1, y1], color+'-')
    plt.text((x1+x2)/2, (y1+y2)/2, name,
             color=color,
             horizontalalignment='center',
             verticalalignment='center',)

def plot_angles(chunks, y1, y2, delx, color = 'k'):
    x0 = 0
    for chunk in chunks:
        plt.plot([x0+delt, x0+delx+delt], [y1, y2], color+':')
        plt.plot([x0 + chunk[1]-delt, x0+delx+chunk[1]-delt], [y1, y2], color+':')
        x0 += chunk[1]

def plot_chunks(chunks, y1, y2):
    x0 = 0
    for chunk in chunks:
        rectangle(x0, x0 + chunk[1], y1, y2, chunk[0], chunk[2])
        x0 += chunk[1]

address_len = 19
auth_overhead = 16
publickeybytes = 32
layer_overhead = address_len + auth_overhead + publickeybytes
secret_length = 17

chunks = [['$P_0$', publickeybytes, 'k'],
          ['$A_0$', auth_overhead, 'r'],
          ['$D_0$', address_len, 'r'],
          ['$P_1$', publickeybytes, 'r'],
          ['$A_1$', auth_overhead, 'r'],
          ['$D_1$', address_len, 'r'],
          ['$P_2$', publickeybytes, 'r'],
          ['$A_2$', auth_overhead, 'r'],
          ['$S$', secret_length, 'r'],
          ['$0\cdots$', layer_overhead, 'c'],
]

y0 = 0
dely = 7
gapy = 3*dely
plot_chunks(chunks, y0, y0 + dely)

while len(chunks) > 3 and chunks[2][0] != '$S$':
    plot_angles(chunks[2:], y0 + gapy, y0 + dely, auth_overhead + publickeybytes, 'r')
    chunks = chunks[2:]
    y0 += gapy
    chunks[0][2] = 'k'
    chunks[1][2] = 'k'
    chunks[-1][2] = 'r'
    plot_chunks(chunks, y0, y0 + dely)

    chunks = chunks[1:]
    plot_angles(chunks, y0 + gapy, y0 + dely, address_len, 'k')
    for i in range(len(chunks)):
        chunks[i][2] = 'r'
    chunks[0][2] = 'k'
    chunks.append(['$0\cdots$', layer_overhead, 'c'])

    y0 += gapy
    plot_chunks(chunks, y0, y0 + dely)

plot_angles(chunks[2:], y0 + gapy, y0 + dely, auth_overhead + publickeybytes, 'r')
chunks = chunks[2:]
y0 += gapy
chunks[0][2] = 'k'
chunks[-1][2] = 'r'
plot_chunks(chunks, y0, y0 + dely)

plt.axes().set_aspect('equal')
plt.axis('off')

plt.tight_layout()

plt.savefig('onion-decryption.pdf')
