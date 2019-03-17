#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2017-2018 Alan Frost. All rights reserved.

Generate static image gallery HTML as masonary layout or carousel

> python gallery.py -t "Susan Frost's Gallery" -p index.html masonary > t
> python gallery.py -t "Susan Frost's Gallery" -p gallery.html gallery > t
> python gallery.py -t "Prints by Susan Frost" -p prints.html -m Print gallery > t
"""
from __future__ import print_function

from string import Template
import argparse
import csv
import json
import sys


def parse_options():
    """ Parse command line options
    """
    parser = argparse.ArgumentParser(description='Image Gallery HTML Generator')
    parser.add_argument('-i', '--images', action='store', default='images.json', help='images.json')
    parser.add_argument('-m', '--medium', action='store', default='*')
    parser.add_argument('-p', '--page', action='store', default='gallery.html')
    parser.add_argument('-s', '--site', action='store', default='https://susanafrost.com')
    parser.add_argument('-t', '--title', action='store', default='Susan Frost')
    parser.add_argument('command', action='store', help='check, csv, gallery, masonary, search')
    return parser.parse_args()

def load_images(images_file):
    """ Load the images.json file
    Args:
        images filename
    """
    images = None
    try:
        with open(images_file) as json_file:
            images = json.load(json_file)
    except (IOError, ValueError) as err:
        print('Load of images file failed:', err.message)

    return images

def read_csv(csv_file):
    """ Read a CSV file with visual art work metadata
    Args:
        csv filename
    Return:
        array of row objects
    """
    csv_rows = []
    with open(csv_file) as csvfile:
        reader = csv.DictReader(csvfile)
        field = reader.fieldnames
        for row in reader:
            csv_rows.extend([{field[i]:row[field[i]] for i in range(len(field))}])
        return csv_rows

def write_csv(images):
    """ Write a CSV file with visual art work metadata
    Args:
        images dict
    """
    fieldnames = ['title', 'medium', 'size', 'created', 'image']
    writer = csv.DictWriter(sys.stdout, fieldnames)
    writer.writeheader()
    for image in images:
        writer.writerow(image)

def check_images(images):
    """ Check an images dict for required visual art work metadata. See
        http://schema.org/VisualArtwork for all sorts of metadata that could be added.
    Args:
        images dict
    """
    for image in images:
        if 'title' not in image:
            if 'image' in image:
                print('Missing "title" from: ' + image['image'])
        else:
            title = image['title']
            if 'created' not in image:
                print('Missing "created" from: ' + title)
            if 'image' not in image:
                print('Missing "image" from: ' + title)
            if 'size' not in image:
                print('Missing "size" from: ' + title)
            if 'medium' not in image:
                print('Missing "medium" from: ' + title)

def generate_masonary_page(site, page, title, images, medium='*'):
    """ Generate HTML masonary layput
    Args:
        site name
        page name
        images dict
        medium filter (e.g. Oil, Print...)
    """
    with open('header.html') as html_file:
        template = Template(html_file.read())
        contents = template.substitute(title=title, page='/' + page)
        print(contents)

    html = '<!-- Modal Image -->\n'
    html += '<div id="imgModal" class="modal">\n'
    html += '  <span class="modal-close" onclick="closeGalleryImage()">&times;</span>\n'
    html += '  <img class="modal-content" id="modal-content">\n'
    html += '  <div id="modal-caption" class="modal-caption"></div>\n'
    html += '</div>\n'
    html += '  <div class="container">\n'
    html += '    <h1>' + title + '</h1>\n'
    html += '    <hr>\n'
    html += '    <div class="row">\n'
    html += '    <div class="col-md-12">\n'
    html += '    <div class="gal">'
    print(html)

    slide = 0
    for image in images:
        if medium == '*' or medium in image['medium']:
            title = image['title']
            caption =  image['medium'] + ', ' + image['size'] + ', ' + image['created']
            img_small = image['image'].replace('.jpg', '_small.jpg')
            html = '      <a href="gallery.html?slide=' + str(slide) + '" title="' + title + ',' + caption + '">'
            #print(html)
            html = '      <img src="static/img/' + img_small + '" alt="' + title
            html += '" onclick="openGalleryImage(' + str(slide) + ')" class="hover-shadow">'
            print(html)
            slide += 1

    html = '    </div>\n'
    html += '    </div>\n'
    html += '    </div>\n'
    html += '  </div>\n'
    print(html)

    with open('footer.html') as html_file:
        contents = html_file.read()
        print(contents)

def generate_gallery_indicators(images, medium='*'):
    """ Generate gallery indicators
    Args:
        images dict
        medium filter (e.g. Oil, Print...)
    """
    html = '        <!-- Indicators -->\n'
    if medium != '*':
        filtered_images = []
        for image in images:
            if medium in image['medium']:
                filtered_images.append(image)
        images = filtered_images

    if len(images) < 12:
        html += '        <ol class="carousel-indicators">\n'
        html += '          <li data-target="#artCarousel" data-slide-to="0" class="active"></li>\n'
        for item in range(1, len(images)):
            html += '          <li data-target="#artCarousel" data-slide-to="' + str(item) + '"></li>\n'
        html += '       </ol>\n'
    print(html)

def generate_search_list(images):
    slide = 0
    html = ''
    for image in images:
        title = image['title']
        #thumb = image['image'].replace('.jpg', '_thumb.jpg')
        #html += '<li><a href="gallery.html?slide=' + str(slide) + '">' + title + '<img src="static/img/' + thumb + '"></a></li>\n'
        html += '<li><a href="gallery.html?slide=' + str(slide) + '">' + title + '</a></li>\n'
        slide += 1
    print(html)

def generate_gallery(site, images, medium='*'):
    """ Generate HTML gallery layput
    Args:
        site name
        images dict
        medium filter (e.g. Oil, Print...)
    """
    slide = 0
    #img_path = site + 'static/img/'
    img_path = 'static/img/'

    html = '  <section class="slide-wrapper">\n'
    html += '    <div class="container">\n'
    html += '      <div id="artCarousel" class="carousel slide carousel-fade" data-ride="carousel" data-interval="false">\n'
    print(html)
    generate_gallery_indicators(images, medium)
    html = '        <!-- Wrapper for slides -->\n'
    html += '        <div class="carousel-inner" role="listbox">\n'

    for image in images:
        if medium != '*' and medium not in image['medium']:
            continue
        title = image['title']
        img_hd = image['image'].replace('.jpg', '_hd.jpg')
        img_med = image['image'].replace('.jpg', '_medium.jpg')
        img_small = image['image'].replace('.jpg', '_small.jpg')
        html += '          <div class="item item' + str(slide)
        if slide == 0:
            html += ' active'
        html += '">\n'
        html += '            <div class="fill" style=" background-color:#48c3af;">\n'
        html += '              <div class="inner-content">\n'
        html += '                <div class="carousel-img">\n'
        html += '                <a href="' + img_path + img_hd + '">\n'
        html += '                <picture>\n'
        html += '                  <source srcset="' + img_path + img_hd + '" media="(min-width: 1400px)">\n'
        html += '                  <source srcset="' + img_path + img_med + '" media="(min-width: 768px)">\n'
        html += '                  <source srcset="' + img_path + img_small + '" media="(min-width: 576px)">\n'
        html += '                  <img srcset="' + img_path + img_small + '" alt="responsive image" class="img img-responsive">\n'
        html += '                </picture>\n'
        html += '                </a>\n'
        #html += '                  <img src="' + site + 'static/img/' + img_hd + '" alt="' + title + '" class="img img-responsive" />\n'
        html += '                </div>\n'
        html += '                <div class="carousel-desc">\n'
        html += '                  <h3>' + title + '</h3>\n'
        html += '                  <p>' + image['medium'] + ', ' + image['size'] + ', ' + image['created'] + '</p>\n'
        html += '                </div>\n'
        html += '              </div>\n'
        html += '            </div>\n'
        html += '          </div>\n'
        slide += 1

    html += '        </div>\n'
    html += '        <!-- Left and right controls -->\n'
    html += '        <a class="left carousel-control" href="#artCarousel" data-slide="prev">\n'
    html += '            <span class="fa fa-chevron-left"></span>\n'
    html += '            <span class="sr-only">Previous</span>\n'
    html += '        </a>\n'
    html += '        <a class="right carousel-control" href="#artCarousel" data-slide="next">\n'
    html += '            <span class="fa fa-chevron-right"></span>\n'
    html += '            <span class="sr-only">Next</span>\n'
    html += '        </a>\n'
    #html += '        <div id="carouselButtons">\n'
    #html += '          <button id="playButton" type="button" class="btn btn-default btn-xs">\n'
    #html += '            <span class="fa fa-play"></span>\n'
    #html += '          </button>\n'
    #html += '        </div>\n'
    html += '      </div>\n'
    html += '    </div>\n'
    html += '  </section>\n'
    print(html)

def generate_gallery_page(site, page, title, images, medium='*'):
    """ Generate HTML gallery layput
    Args:
        site name
        page name
        title
        images dict
        medium filter (e.g. Oil, Print...)
    """
    with open('header.html') as html_file:
        template = Template(html_file.read())
        contents = template.substitute(title=title, page='/' + page)
        print(contents)
    generate_gallery(site, images, medium)
    with open('footer.html') as html_file:
        contents = html_file.read()
        print(contents)

def main():
    """ Main program
    """
    options = parse_options()
    images = load_images(options.images)
    if images is None:
        print('No images loaded')
        return
    else:
        pass #print('Loaded {} images'.format(len(images)))
    site = options.site
    if len(site) > 1:
        site += '/'
    if options.command == 'check':
        if images is not None:
            print('Images loaded')
            check_images(images)
    elif options.command == 'csv':
        write_csv(images)
    elif options.command == 'masonary':
        generate_masonary_page(site, options.page, options.title, images, options.medium)
    elif options.command == 'gallery':
        generate_gallery_page(site, options.page, options.title, images, options.medium)
    elif options.command == 'search':
        generate_search_list(images)

if __name__ == '__main__':
    main()
