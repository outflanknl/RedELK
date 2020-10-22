import shelve
import codecs
import os
from hashlib import md5
import helper

### CONSTANTS
secret = "YOURSECRETHERE"
fileTable = { -1 : "error.txt",
              0 : "default.txt",
              1 : "proxy.txt",
              2 : "payload.txt"}

for i in range(3,5):
    fileTable[i] = "payload2.txt"

for i in range(5,99):
    fileTable[i] = "monkey.jpg"

## usage:
# http://127.0.0.1:18080/keyer/6d8ad2e4d8df9debfb2c026e81ba6635b6d76f1518e982736bdb4511588eefae/test
# basic url or redirector.....................|modname|key.....|notused
class f():
  def __init__(self,key,h,req={}):
    self.key = key.encode("utf-8",'ignore')
    cwd = os.path.dirname(os.path.realpath(__file__))
    self.folder = cwd
    self.scoreRes = self.score()
    if self.scoreRes in fileTable:
        self.returnFile = fileTable[self.scoreRes]
    else:
        self.returnFile = fileTable[0]

  def score(self):
    d = shelve.open('%s/data.shelve'%self.folder)
    if len(self.key) != 64:
      return(False)
    stok = self.key[:32]
    tok = self.key[32:]
    if stok == md5("%s%s"%(secret,tok)).hexdigest():
      #the key is valid
      if not d.has_key(self.key):
        #the key is new
        d[self.key] = 1
        return(1)
      else:
        d[self.key] += 1
        return(d[self.key])
    return(-1)

  def fileContent(self):
    ff = self.returnFile
    with open("%s/%s"%(self.folder,ff), 'rb') as f:
      return f.read()

  def fileType(self):
    ff = self.returnFile.split('.')[1]
    return(helper.getContentType(ff))

def newKey():
  from hashlib import md5
  from time import time
  tok = md5(str(time())).hexdigest()
  stok = md5("%s%s"%(secret,tok)).hexdigest()
  key = "%s%s"%(stok,tok)
  return(key)
