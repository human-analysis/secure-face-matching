
# ///////////// Copyright 2018 Vishnu Boddeti. All rights reserved. /////////////
# //
# //   Project     : Secure Face Matching (Eyeverify/Zoloz)
# //   File        : gendata.py
# //   Description : generated fake 512-dimensional face features for testing
# //
# //
# //   Created On: 05/01/2018
# //   Created By: Vishnu Boddeti <mailto:vishnu@msu.edu>
# ////////////////////////////////////////////////////////////////////////////

import struct
import numpy as np

dim = 64
num1 = 5
num2 = 5

data1 = np.float32(np.random.randn(num1, dim))
data2 = np.float32(np.random.randn(num2, dim))
data2 = data1.copy()

data1 = data1 / np.linalg.norm(data1, ord=2, axis=1, keepdims=True)
data2 = data2 / np.linalg.norm(data2, ord=2, axis=1, keepdims=True)

precision = 125
d1 = np.round(data1 * precision)
d2 = np.round(data2 * precision)
score = np.dot(d1, d2.transpose()) / (precision * precision)
print(score)

data1 = data1.flatten()
data2 = data2.flatten()

data1 = np.ndarray.tolist(data1)
data2 = np.ndarray.tolist(data2)

size1 = [num1, dim]
size2 = [num2, dim]

f = open('gallery.bin', 'wb')
s = struct.pack('i' * len(size1), *size1)
f.write(s)
s = struct.pack('f' * len(data1), *data1)
f.write(s)
f.close()

f = open('probe.bin', 'wb')
s = struct.pack('i' * len(size2), *size2)
f.write(s)
s = struct.pack('f' * len(data2), *data2)
f.write(s)
f.close()
