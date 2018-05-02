#!/usr/bin python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2017 Alan Frost, Inc. All rights reserved.

Process a jpg image to orient and resize for a responsive srcset

> python image.py -f image.jpy info
> python image.py -f image.jpy process
"""

from __future__ import print_function

import argparse
import json
import shlex
import subprocess

from PIL import Image

HD_WIDTH = 1400
MEDIUM_WIDTH = 768
SMALL_WIDTH = 576
THUMB_WIDTH = 100

def orient_image(srcfile, orientation):
    """ Load image from source file and correct orientation
    Args:
        srcfile to load image from
        EXIF orientation
    Returns:
        image
    """
    rotation = 0
    degrees = ''.join(filter(str.isdigit, orientation.encode('utf-8')))
    if degrees:
        rotation = int(degrees)
        # EXIF orientation is degrees clockwise, image.rotate is degrees counter clockwise
        if 'CW' in orientation and 'CCW' not in orientation:
            rotation = rotation * -1
        print('Orient {}'.format(rotation))
    # rotate image
    img = Image.open(srcfile)
    size = (img.size[0] / 2, img.size[1] / 2)
    print(size)
    if rotation != 0:
        img2 = img.rotate(rotation, expand=True)
        size = (img2.size[0] / 2, img2.size[1] / 2)
        print(size)
        return img2
    return img

def create_srcset(srcfile, img):
    thumbfile = srcfile.replace('.jpg', '_thumb.jpg')
    smallfile = srcfile.replace('.jpg', '_small.jpg')
    mediumfile = srcfile.replace('.jpg', '_medium.jpg')
    hdfile = srcfile.replace('.jpg', '_hd.jpg')

    scale = float(HD_WIDTH) / float(img.size[0])
    size = (int(img.size[0] * scale), int(img.size[1] *scale))
    oimg = img.resize(size)
    oimg.save(hdfile, 'JPEG')

    scale = float(MEDIUM_WIDTH) / float(img.size[0])
    size = (int(img.size[0] * scale), int(img.size[1] *scale))
    oimg = img.resize(size)
    oimg.save(mediumfile, 'JPEG')

    scale = float(SMALL_WIDTH) / float(img.size[0])
    size = (int(img.size[0] * scale), int(img.size[1] *scale))
    oimg = img.resize(size)
    oimg.save(smallfile, 'JPEG')

    img.thumbnail((THUMB_WIDTH, THUMB_WIDTH))
    img.save(thumbfile, 'JPEG')
    img.show()

def parse_options():
    """ Parse command line options
    """
    parser = argparse.ArgumentParser(description='Image processing app')
    parser.add_argument('-f', '--file', action="store")
    parser.add_argument('-r', '--rotate', action="store")
    parser.add_argument('command', action='store', help='info, process')
    return parser.parse_args()

def main():
    """ Main program
    """
    options = parse_options()
    srcfile = options.file
    orientation = options.rotate
    if not srcfile:
        print('No image file specified, use -f <image>')
    if srcfile.endswith('.jpg'):
        if not orientation:
            exif_command = "exiftool -j '%s'" % srcfile
            exif = json.loads(subprocess.check_output(shlex.split(exif_command), stderr=subprocess.PIPE))
            orientation = 'None'
            if 'Orientation' in exif[0]:
                orientation = exif[0]['Orientation']
            if 'ImageWidth' in exif[0]:
                width = exif[0]['ImageWidth']
            if 'ImageHeight' in exif[0]:
                height = exif[0]['ImageHeight']

        if options.command == 'info':
            print('Width={} Height={} Orientation={}'.format(width, height, orientation))
        elif options.command == 'process':
            img = orient_image(srcfile, orientation)
            create_srcset(srcfile, img)

if __name__ == '__main__':
    main()
