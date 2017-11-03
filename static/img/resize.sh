#!/usr/bin/env bash
# Resize images for responsive image display

# max height
LARGE_WIDTH=1120
MEDIUM_WIDTH=840
SMALL_WIDTH=400

identify -format "%wx%h" ${1}

filename=${1##*/}
imagename=${filename%%.*}
extension=${filename#*.}

convert ${1} -resize ${SMALL_WIDTH} ${imagename}_small.${extension}
convert ${1} -resize ${MEDIUM_WIDTH} ${imagename}_medium.${extension}
convert ${1} -resize ${LARGE_WIDTH} ${filename}
