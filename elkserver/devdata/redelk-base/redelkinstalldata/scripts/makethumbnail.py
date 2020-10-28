#!/usr/bin/python3
#
# Part of Red ELK
# Script to generate thumbnails of images 
# The output is saved next to input file as ".thumb.jpg" 
#
# Author: Outflank B.V. / Marc Smeets
#

try:
  from PIL import Image
  import sys, os, syslog#, fnmatch

  path = sys.argv[1]
  baseheight = 300
  for root, dirs, files in os.walk(path):
    for file in files:
      if file.endswith(".jpg") and not file.endswith("thumb.jpg"):
        filein = os.path.join(root, file)
        fileout = (filein + ".thumb.jpg")
        if not os.path.exists(fileout):
          img = Image.open(filein)
          wpercent = (baseheight/float(img.size[1]))
          vsize = int((float(img.size[0])*float(wpercent)))
          img = img.resize((vsize,baseheight), Image.ANTIALIAS)
          img.save(fileout)

except:
  e = sys.exc_info()[1]
  syslog.syslog('RedELK - makethumbnail.py : Error '+ str(e))
