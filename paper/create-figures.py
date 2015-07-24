#!/usr/bin/python3

import matplotlib, copy
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

plt.figure(figsize=(8,10))

delt = 0.2

class Datum:
    def __init__(self, name, size, offset, colors = ['k']):
        self.name = name
        self.size = size
        self.offset = offset
        self.colors = colors
    def encrypt(self, color):
        if self.colors[0] == color:
            self.colors = self.colors[1:]
        else:
            print('colors are', self.colors)
            self.colors = [color] + self.colors
    def decrypt(self, color):
        assert(self.colors[0] == color)
        self.colors = self.colors[1:]
    def shift(self, offset):
        self.offset += offset

    def rectangle(self, y1, y2, thickness = 0.5):
        x1 = self.offset + thickness
        x2 = self.offset + self.size - thickness
        for c in self.colors:
            plt.plot([x1, x1, x2, x2, x1],
                     [y1, y2, y2, y1, y1], c+'-')
            x1 += thickness
            x2 -= thickness
            y1 += thickness
            y2 -= thickness
        plt.text((x1+x2)/2, (y1+y2)/2, self.name,
                 color = self.colors[0],
                 horizontalalignment='center',
                 verticalalignment='center')
    def __repr__(self):
        return '[%2d %s (%2d) %s]' % (self.offset, self.name, self.size, self.colors)

def AppendDatum(data, name, size, color = 'k'):
    if len(data) == 0:
        return [Datum(name, size, 0, [color])]
    else:
        last = data[-1]
        return data + [Datum(name, size, last.offset + last.size, [color])]

def CutData(data, cutsize):
    while data[0].offset + data[0].size <= cutsize:
        data = data[1:]
    if data[0].offset < cutsize:
        data[0].size -= cutsize - data[0].offset
        data[0].offset = cutsize
        print(data[0].name, 'is cut to size', data[0].size)
    return data

colorcycle = ['r', 'b', 'm', 'y']
def EncryptData(data, i):
    data = CutData(data, 16 + auth_overhead)
    data = [Datum(r'$0\cdots$', 16, 0, ['g']),
            Datum(r'$A_%d$' % i, auth_overhead, 16, [colorcycle[i]])] + data
    for d in data[2:]:
        d.encrypt(colorcycle[i])
    return data

def ShiftLeftAndPad(data, shift):
    newd = []
    for d in data:
        if d.offset + d.size - shift < 0:
            pass
        elif d.offset - shift < 0:
            d.size -= shift - d.offset
            d.offset = 0
            newd += [d]
        else:
            d.offset -= shift
            newd += [d]
    return AppendDatum(newd, r'$0\cdots$', shift, 'c')

def ShiftRight(data, shift):
    for d in data:
        d.offset += shift
    return data[:-1]

def AnnounceTransformation(data, words, y, color = 'k'):
    width = sum([d.size for d in data])
    stylename = 'rarrow'
    plt.text(width/2, y, words, rotation=0,
             color = color,
             size = 8,
             horizontalalignment='center', verticalalignment='center',
             bbox=dict(boxstyle=stylename, fc="w", ec=color))

address_len = 19
auth_overhead = 16
publickeybytes = 32
layer_overhead = address_len + auth_overhead + publickeybytes
secret_length = 7
num_layers = 3

transmitted_length = secret_length + auth_overhead + (num_layers-1)*layer_overhead
cb_length = 16 + transmitted_length + layer_overhead

data = [Datum('', 16 + (num_layers+1)*layer_overhead + (secret_length-address_len-publickeybytes), 0, ['g'])]

y0 = 0
dely = 7
gapy = 4*dely

ytop = dely-gapy
ybottom = -num_layers*4*gapy - dely

plt.plot([16, 16],
         [ytop, ybottom-dely], 'k:')
plt.plot([16 + transmitted_length, 16 + transmitted_length],
         [ytop, ybottom-dely], 'k:')

plt.plot([0, 0],
         [ytop, ybottom], 'r:')
plt.plot([cb_length, cb_length],
         [ytop, ybottom], 'r:')

def annotate_dim(xyfrom,xyto,text):
    plt.annotate("",xyfrom,xyto,arrowprops=dict(arrowstyle='<->'))
    plt.text(cb_length/2,(xyto[1]+xyfrom[1])/2,text,fontsize=10,
             ha='center', va='center',
             bbox=dict(boxstyle='square', fc="w", ec='w'))
annotate_dim([0, ybottom], [cb_length, ybottom], 'crypto_box length')
annotate_dim([16, ybottom-dely], [16+transmitted_length, ybottom-dely], 'transmitted length')

for i in range(num_layers):
    if i > 0:
        AnnounceTransformation(data, 'Shift left and pad', y0 - gapy/2 + dely/2)
    data = ShiftLeftAndPad(data, layer_overhead)
    y0 -= gapy
    for d in data:
        d.rectangle(y0, y0+dely)

    AnnounceTransformation(data, 'Encrypt %d' % i, y0 - gapy/2 + dely/2, colorcycle[i])
    data = EncryptData(data, i)
    y0 -= gapy
    for d in data:
        d.rectangle(y0, y0+dely)

# Here we insert the secret information!
AnnounceTransformation(data, 'Insert secret!', y0 - gapy/2 + dely/2)
data = [Datum('', 16 + auth_overhead, 0, ['g']),
        Datum('$S$', secret_length, 16 + auth_overhead,
              ['k'])] + CutData(data, 16+auth_overhead+secret_length)
y0 -= gapy
for d in data:
    d.rectangle(y0, y0+dely)

for i in range(num_layers-1,-1,-1):
    AnnounceTransformation(data, 'Encrypt %d' % i, y0 - gapy/2 + dely/2, colorcycle[i])
    data = EncryptData(data, i)
    y0 -= gapy
    for d in data:
        d.rectangle(y0, y0+dely)

    if i == 0:
        break
    
    AnnounceTransformation(data, 'Shift right and add data', y0 - gapy/2 + dely/2)
    data = [Datum(r'$0\cdots$', 16 + auth_overhead, 0, ['c']),
            Datum(r'$a_%d$' % i, address_len, 16+auth_overhead, ['k']),
            Datum(r'$P_%d$' % i, publickeybytes, 16+auth_overhead+address_len,
                  ['k'])] + ShiftRight(data, layer_overhead)[1:]
    y0 -= gapy
    for d in data:
        d.rectangle(y0, y0+dely)

plt.axes().set_aspect('equal')
plt.axis('off')

plt.tight_layout()

plt.savefig('onion-encryption.pdf')
