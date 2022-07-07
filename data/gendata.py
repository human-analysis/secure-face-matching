
# ///////////// Copyright 2018 Vishnu Boddeti. All rights reserved. /////////////
# //
# //   Project     : Secure Face Matching (Eyeverify/Zoloz)
# //   File        : gendata.py
# //   Description : generated fake 512-dimensional face features for testing
# //
# //
# //   Created On: 05/01/2018
# //   Created By: Vishnu Boddeti <mailto:vishnu@msu.edu>
# //   Modified On: 03/01/2020
# ////////////////////////////////////////////////////////////////////////////

import struct
import numpy as np


def write_to_file(name, data, siz):
    f = open(name, 'wb')
    s = struct.pack('i' * len(siz), *siz)
    f.write(s)
    s = struct.pack('f' * len(data), *data)
    f.write(s)
    f.close()


dim = 512
num1 = 16
num2 = 16

data1 = np.float32(np.random.randn(num1, dim))
data2 = np.float32(np.random.randn(num2, dim))
# data2 = data1.copy()

data1 = data1 / np.linalg.norm(data1, ord=2, axis=1, keepdims=True)
data2 = data2 / np.linalg.norm(data2, ord=2, axis=1, keepdims=True)

precision = 125
d1 = np.round(data1 * precision)
d2 = np.round(data2 * precision)
score = np.dot(d1, d2.transpose()) / (precision * precision)
print(score)

# save in 1-to-1 format
d1 = data1.flatten()
d2 = data2.flatten()

d1 = np.ndarray.tolist(d1)
d2 = np.ndarray.tolist(d2)

size1 = [num1, dim]
size2 = [num2, dim]

write_to_file('probe-1-to-1.bin', d2, size2)
write_to_file('gallery-1-to-1.bin', d1, size1)

# save in 1-to-n format
data1 = data1.transpose()
data2 = data2.transpose()
d1 = data1.flatten()
d2 = data2.flatten()

d1 = np.ndarray.tolist(d1)
d2 = np.ndarray.tolist(d2)

size1 = [dim, num1]
size2 = [dim, num2]

write_to_file('probe-1-to-n.bin', d2, size2)
write_to_file('gallery-1-to-n.bin', d1, size1)
