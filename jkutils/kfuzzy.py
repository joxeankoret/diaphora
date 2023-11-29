#!/usr/bin/env python

"""
Fuzzy hashing algorithms
Copyright (C) 2009-2023, Joxean Koret

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
"""

import os
import sys
import base64
import functools

__all__ = ["CKoretFuzzyHashing"]

#-------------------------------------------------------------------------------
def modsum(buf):
  """ Return the SUM(BUF) MOD 255 """
  return sum(buf) % 255

#-------------------------------------------------------------------------------
class CFileStr(str):
  """
  Files wrapper class
  """
  def __init__(self, fd):
    str.__init__(self)
    self.fd = fd

  def __getslice__(self, x, y):
    self.fd.seek(x, 0)
    buf = self.fd.read(y-x)
    self.fd.seek(y)
    return buf

  def __len__(self):
    old = self.fd.tell()
    self.fd.seek(0, 2)
    pos = self.fd.tell()
    self.fd.seek(old)
    return pos

#-------------------------------------------------------------------------------
class CKoretFuzzyHashing:
  """ Generate fuzzy hashes of files or bytes """
  bsize = 512
  output_size = 32
  ignore_range = 2
  big_file_size = 1024*1024*10
  algorithm = None
  reduce_errors = True
  remove_spaces = False

  def get_bytes(self, f, initial, final):
    """
    Get bytes from @initial to @final
    """
    f.seek(initial)
    return f.read(final)

  def edit_distance(self, sign1, sign2):
    """
    Trivially calculate the edit distance of @sign1 to @sign2
    """
    if sign1 == sign2:
      return 0
    
    m = max(len(sign1), len(sign2))
    distance = 0
    
    for c in range(0, m):
      if sign1[c:c+1] != sign2[c:c+1]:
        distance += 1
    
    return distance

  def simplified(self, strbytes, _):
    """
    Get a simplified hash
    """
    output_size = self.output_size
    bsize = self.bsize
    total_size = len(strbytes)
    size = (total_size/bsize) / output_size
    buf = []
    reduce_errors = self.reduce_errors
    # Adjust the output to the desired output size
    for c in range(0, output_size):
      tmp = strbytes[c*size:(c*size+1)+bsize]
      ret = sum(map(ord, tmp)) % 255
      if reduce_errors:
        if ret != 255 and ret != 0:
          buf.append(chr(ret))
      else:
        buf.append(chr(ret))
    
    buf = "".join(buf)
    return base64.b64encode(buf).strip("=")[:output_size]

  def _hash(self, strbytes, aggresive = False):
    """
    Internal hashing method
    """
    idx = 0
    ret = []
    
    output_size = self.output_size
    ignore_range = self.ignore_range
    bsize = self.bsize
    total_size = len(strbytes)
    rappend = ret.append
    reduce_errors = self.reduce_errors
    # Calculate the sum of every block
    while 1:
      chunk_size = idx*bsize
      buf = strbytes[chunk_size:chunk_size+bsize]
      char = modsum(buf)

      if reduce_errors:
        if char != 255 and char != 0:
          rappend(chr(char))
      else:
        rappend(chr(char))

      idx += 1

      if chunk_size+bsize > total_size:
        break

    ret = "".join(ret)
    size = len(ret) / output_size
    size = min(int(size), 1)
    buf = []

    # Adjust the output to the desired output size
    for c in range(0, output_size):
      if aggresive:
        buf.append(ret[c:c+size+1][ignore_range:ignore_range+1])
      else:
        buf.append(ret[c:c+size+1][1:2])

      i = 0
      for x in ret[c:c+size+1]:
        i += 1
        if i != ignore_range:
          continue
        i = 0
        buf += x
        break

    ret = "".join(buf)
    bret = ret.encode()
    return base64.b64encode(bret).strip(b"=")[:output_size]

  def _fast_hash(self, strbytes, _):
    """
    Internal fast hashing method
    """
    i = -1
    ret = set()
    
    output_size = self.output_size
    bsize = self.bsize
    radd = ret.add
    
    while i < output_size:
      i += 1
      buf = strbytes[i*bsize:(i+1)*bsize]
      char = sum(map(ord, buf)) % 255
      if self.reduce_errors:
        if char != 255 and char != 0:
          radd(chr(char))
      else:
        radd(chr(char))
    
    ret = "".join(ret)
    return base64.b64encode(ret).strip("=")[:output_size]

  def xor(self, strbytes):
    """
    Xor all the bytes
    """
    return functools.reduce(lambda x, y: x ^ y, strbytes)

  def _experimental_hash(self, strbytes, _):
    """
    An experimental (since 2009...) internal hasher
    """
    idx = 0
    ret = []
    bsize = self.bsize
    output_size = self.output_size
    size = len(strbytes)
    chunk_size = idx*self.bsize
    byte = None
    
    while size > chunk_size + (bsize/output_size):
      chunk_size = idx*self.bsize
      if byte is None:
        val = bsize
      elif ord(byte) > 0:
        val = ord(byte)
      else:
        val = output_size
      
      buf = strbytes[chunk_size:chunk_size+val]
      byte = self.xor(list(map(ord, buf))) % 255
      byte = chr(byte)
      
      if byte != '\xff' and byte != '\x00':
        ret.append(byte)
      
      idx += 1
    
    ret = "".join(ret)
    buf = ""
    size = len(ret)/output_size
    for n in range(0, output_size):
      buf += ret[n*size:(n*size)+1]
    
    return base64.b64encode(buf).strip("=")[:output_size]

  def mix_blocks(self, strbytes):
    """
    Mix chunks of bytes from the beginning and ending
    """
    idx = 0
    buf = strbytes
    ret = b""
    size1 = 0
    size2 = 0

    while 1:
      size1 = idx*self.bsize
      size2 = (idx+1)*self.bsize
      
      tmp = buf[size1:size2]
      tm2 = tmp
      ret += tmp
      ret += tm2
      
      idx += 1
      
      if len(tmp) < self.bsize:
        break
    
    return ret

  def clean_spaces(self, strbytes):
    """
    Remove all white spaces
    """
    strbytes = strbytes.replace(b" ", b"").replace(b"\r", b"").replace(b"\n", b"")
    strbytes = strbytes.replace(b"\t", b"")
    return strbytes

  def hash_bytes(self, strbytes, aggresive = False):
    """
    Hash the given bytes
    """
    if isinstance(strbytes, str):
      strbytes = strbytes.encode()

    if self.remove_spaces:
      strbytes = self.clean_spaces(strbytes)
    
    mix = self.mix_blocks(strbytes)
    if self.algorithm is None:
      func = self._hash
    else:
      func = self.algorithm
    
    hash1 = func(mix, aggresive)
    hash2 = func(strbytes, aggresive)
    hash3 = func(strbytes[::-1], aggresive)

    return (hash1 + b";" + hash2 + b";" + hash3).decode("utf-8")

  def hash_file(self, filename, aggresive = False):
    """
    Hash the given file's bytes
    """
    with open(filename, "rb") as f:
      f.seek(0, 2)
      size = f.tell()
      
      if size > self.big_file_size:
        print()
        curr_size = size/1024/1024
        big_size = self.big_file_size / 1024 / 1024
        print(f"Warning! Support for big files ({curr_size} MB > {big_size} MB) is broken!")
        fbytes = CFileStr(f)
      else:
        f.seek(0)
        fbytes = f.read()
        f.close()

      return self.hash_bytes(fbytes, aggresive)

#-------------------------------------------------------------------------------
class kdha:
  """ Interface to make partially compatible the KFuzzy hashing algorithms with
  the standard python hashlib format. This is the Koret Default Hashing Algorithm """

  def __init__(self, strbytes):
    """ Initialize the object """
    self.block_size = 512
    self.digest_size = 32
    self._bytes = strbytes
    self._kfd = CKoretFuzzyHashing()

  def update(self, strbytes):
    """ Not very useful, just for compatibility... """
    self._bytes += strbytes

  def hexdigest(self):
    """ Returns and hexadecimal digest """
    self._kfd.bsize = self.block_size
    self._kfd.output_size = self.digest_size
    hasher = self._kfd.hash_bytes(self._bytes)
    return hasher

  def digest(self):
    """ Same as hexdigest """
    return self.hexdigest()

#-------------------------------------------------------------------------------
class kfha(kdha):
  """ Interface to make partially compatible the KFuzzy hashing algorithms with
  the standard python hashlib format. This is the Koret Fast Hashing Algorithm """

  def __init__(self, strbytes):
    kdha.__init__(self, strbytes)
    self._bytes = strbytes
    self._kfd = CKoretFuzzyHashing()
    self._kfd.algorithm = self._kfd._fast_hash

#-------------------------------------------------------------------------------
class ksha(kdha):
  """ Interface to make partially compatible the KFuzzy hashing algorithms with
  the standard python hashlib format. This is the Koret Simplified Hashing Algorithm """

  def __init__(self, strbytes):
    kdha.__init__(self, strbytes)
    self._bytes = strbytes
    self._kfd = CKoretFuzzyHashing()
    self._kfd.algorithm = self._kfd.simplified

#-------------------------------------------------------------------------------
def usage():
  """ Show usage information """
  print("Usage:", sys.argv[0], "<filename>")

#-------------------------------------------------------------------------------
def main(path):
  """
  Hash the given input file name
  """
  hasher = CKoretFuzzyHashing()
  #hasher.algorithm = hasher._fast_hash
  
  if os.path.isdir(path):
    print("Signature;Simple Signature;Reverse Signature;Filename")
    for root, _, files in os.walk(path):
      for name in files:
        tmp = os.path.join(root, name)
        try:
          ret = hasher.hash_file(tmp, True)
          print(f"{ret};{tmp}")
        except:
          print(f"***ERROR with file {tmp}")
          print(sys.exc_info()[1])
  else:
    hasher = CKoretFuzzyHashing()
    ret = hasher.hash_file(path, True)
    print(f"{path};{ret}")

if __name__ == "__main__":
  if len(sys.argv) == 1:
    usage()
  else:
    main(sys.argv[1])
