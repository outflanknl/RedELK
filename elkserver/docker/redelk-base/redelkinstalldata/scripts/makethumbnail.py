#!/usr/bin/python3
"""
Part of Red ELK

Script to generate thumbnails of images
The output is saved next to input file as ".thumb.jpg"

Authors:
- Outflank B.V. / Marc Smeets
- Lorenzo Bernardi (@fastlorenzo)
"""

import sys
import os
import logging
from PIL import Image

logger = logging.getLogger('makethumbnail')

try:

    path = sys.argv[1]
    BAS_HEIGHT = 300
    for root, dirs, files in os.walk(path):
        for file in files:
            if file.endswith('.jpg') and not file.endswith('thumb.jpg'):
                file_in = os.path.join(root, file)
                file_out = (f'{file_in}.thumb.jpg')
                
                if not os.path.exists(file_out):
                    img = Image.open(file_in)
                    w_percent = (BAS_HEIGHT/float(img.size[1]))
                    v_size = int((float(img.size[0])*float(w_percent)))
                    img = img.resize((v_size,BAS_HEIGHT), Image.ANTIALIAS)
                    img.save(file_out)
# pylint: disable=broad-except
except Exception as error:
    error = sys.exc_info()[1]
    logging.log('Error ', str(error))
