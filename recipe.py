#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2017 Alan Frost, All rights reserved.

Implementation of Recipe manager

"""

from datetime import datetime
import re
import os
import simplejson as json

from awsutils import DynamoDB
from utils import generate_id, contains_only

def render_ingredients(ingredients):
    """ Render recipe ingredients as HTML
    Args:
        ingredients: dictionary
    Returns:
        HTML
    """

    if 'title' in ingredients:
        html = '<h5><strong>' + ingredients['title'] + '</strong></h5>\n<ul>\n'
    else:
        html = '<ul>\n'

    index = 1
    while 'item' + str(index) in ingredients:
        item = ingredients.get('item' + str(index))
        quantity = item.get('quantity')
        ingredient = item.get('ingredient')
        fraction = quantity.find('/')
        if fraction != -1:
            if quantity[fraction + 1] == '2':
                quantity = quantity.replace('1/2', '&frac12;')
            elif quantity[fraction + 1] == '4':
                if quantity[fraction - 1] == '1':
                    quantity = quantity.replace('1/4', '&frac14;')
                else:
                    quantity = quantity.replace('3/4', '&frac34;')
            elif quantity[fraction + 1] == '3':
                if quantity[fraction - 1] == '1':
                    quantity = quantity.replace('1/3', '&#8531;')
                else:
                    quantity = quantity.replace('2/3', '&#8532;')
            elif quantity[fraction + 1] == '8':
                if quantity[fraction - 1] == '1':
                    quantity = quantity.replace('1/8', '&#8539;')
                elif quantity[fraction - 1] == '3':
                    quantity = quantity.replace('3/8', '&#8540;')
                elif quantity[fraction - 1] == '5':
                    quantity = quantity.replace('5/8', '&#8541;')
                else:
                    quantity = quantity.replace('7/8', '&#8542;')
        html += '  <li itemprop="ingredients">' + quantity + ' ' + ingredient + '</li>\n'
        index += 1

    html += '</ul>\n'
    return html

def add_times(time_value1, time_value2):
    """ Add preptime and cooktime to make total time
    Args:
        time_value in hours and/or minutes (e.g. "15 mins", "1 hour 30 mins")
    Returns:
        html string
    """
    duration = 0
    minutes = re.search(r'(\d{1,2}) [Mm]in', time_value1)
    hours = re.search(r'(\d{1,2}) [Hh]our', time_value1)
    if hours and hours > 0:
        duration += int(hours.group(1)) * 60
    if minutes and minutes > 0:
        duration += int(minutes.group(1))
    minutes = re.search(r'(\d{1,2}) [Mm]in', time_value2)
    hours = re.search(r'(\d{1,2}) [Hh]our', time_value2)
    if hours and hours > 0:
        duration += int(hours.group(1)) * 60
    if minutes and minutes > 0:
        duration += int(minutes.group(1))
    if duration >= 120:
        total_time = '{} hours {} mins'.format(duration / 60, duration % 60)
    elif duration >= 60:
        total_time = '1 hour {} mins'.format(duration % 60)
    else:
        total_time = '{} mins'.format(duration)
    return total_time

def render_time(time_property, time_value):
    """ Render a recipe time value, and set schema.org properties (ISO 8601 duration)
    Args:
        time_property (prepTime, cookTime or totalTime)
        time_value in hours and/or minutes (e.g. "15 mins", "1 hour 30 mins")
    Returns:
        html string
    """
    minutes = re.search(r'(\d{1,2}) [Mm]in', time_value)
    hours = re.search(r'(\d{1,2}) [Hh]our', time_value)
    duration = 'PT'
    if hours and hours > 0:
        duration += str(hours.group(1)) + 'H'
    if minutes and minutes > 0:
        duration += str(minutes.group(1)) + 'M'
    if time_property == 'prepTime':
        time_value = time_value + ' preparation'
    elif time_property == 'cookTime':
        time_value = time_value + ' cooking'
    html = '<h5><meta itemprop="' + time_property + '" datetime="' + duration + '">'
    html += '<i class="fa fa-clock-o fa-fw" aria-hidden="true"></i>&nbsp;' + time_value + '</h5>\n'
    return html

def render_instructions(instructions, mode):
    """ Render recipe instructions as HTML
    Args:
        instructions: dictionary
        mode: make or read
    Returns:
        HTML
    """

    html = ''
    if 'title' in instructions:
        html = '<h5><strong>' + instructions['title'] + '</strong></h5>\n'

    if mode == 'make':
        html += '<ol itemprop="recipeInstructions">\n'
    else:
        html += '<p itemprop="recipeInstructions">\n'
    index = 1
    while 'step' + str(index) in instructions:
        item = instructions.get('step' + str(index))
        item = item.replace('degrees', '&#8457;')
        item = item.replace('saute', 'saut&eacute;')
        if mode == 'make':
            html += '  <li>' + item + '</li>\n'
        else:
            html += item + '. '
        index += 1
    if mode == 'make':
        html += '</ol>\n'
    else:
        html += '</p>\n'
    return html

def render_recipe(recipe, mode='read'):
    """ Render a recipe as HTML
    Args:
        recipe: dictionary
    Returns:
        HTML
    """

    image = ''
    html = '<div class="col-sm-8">\n'
    title = recipe['title']
    html += '<meta itemprop="url" content="https://cyberfrosty.com/recipe.html?recipe=' + title + '" />\n'
    if 'image' in recipe:
        image, ext = os.path.splitext(recipe['image'])
        small = image + '_small' + ext
        medium = image + '_medium' + ext
        large = image + ext
    else:
        image = '/img/' + title.replace(' ', '')
        small = image + '_small.jpg'
        medium = image + '_medium.jpg'
        large = image + '.jpg'
    if 'image' in recipe or os.path.isfile('static' + large):
        html += '<img  itemprop="image" src="' + large + '" alt="' + title + '" ' \
                'srcset="' + large + ' 1120w,' + medium + ' 720w,' + small + ' 400w" ' \
                'sizes="(min-width: 40em) calc(66.6vw - 4em) 100vw">\n'
        html += '</div><!--/col-sm-8-->\n'
        html += '<div class="col-sm-4">\n'
        if 'description' in recipe:
            html += '<h5 itemprop="description"><i class="fa fa-newspaper-o fa-fw" aria-hidden="true"></i>&nbsp;' + recipe['description'] + '</h5><br />\n'
        if 'chef' in recipe:
            html += '<h5 itemprop="author"><i class="fa fa-cutlery fa-fw" aria-hidden="true"></i>&nbsp;Chef ' + recipe['chef'] + '</h5>\n'
        if 'yield' in recipe:
            yields = recipe['yield']
            if 'Serves' in yields:
                icon = '<i class="fa fa-group fa-fw" aria-hidden="true">'
            else:
                icon = '<i class="fa fa-clone fa-fw" aria-hidden="true">'
            html += '<h5 itemprop="recipeYield">' + icon + '</i>&nbsp;' + yields + '</h5>\n'
        total_time = None
        if 'preptime' in recipe:
            html += render_time('prepTime', recipe['preptime'])
            total_time = recipe['preptime']
        if 'cooktime' in recipe:
            html += render_time('cookTime', recipe['cooktime'])
            total_time = add_times(total_time, recipe['cooktime']) if total_time else recipe['cooktime']
        if 'totaltime' in recipe:
            html += render_time('totalTime', recipe['totaltime'])
        elif 'time' in recipe:
            html += render_time('totalTime', recipe['time'])
        elif total_time:
            html += render_time('totalTime', total_time)
        if 'date' in recipe:
            posted = datetime.strptime(recipe['date'], '%B %d, %Y').strftime('%Y-%m-%d')
            html += '<h5 itemprop="datePublished" content="' + posted + '">'
            html += '<i class="fa fa-calendar fa-fw" aria-hidden="true"></i>&nbsp;' + recipe['date'] + '</h5>\n'
        if 'rating' in recipe:
            rating = recipe['rating']
            reviews = 1
            html += '<h5 itemprop="aggregateRating" itemscope itemtype="http://schema.org/AggregateRating">\n'
            html += '<meta itemprop="ratingValue" content="' + str(rating) + '">\n'
            html += '<meta itemprop="reviewCount" content="' + str(reviews) + '">\n'
            for i in range(5):
                if rating > 0.75:
                    html += '<span class="fa fa-star star-checked"></span>\n'
                elif rating > 0.25:
                    html += '<span class="fa fa-star-half-o star-checked"></span>\n'
                else:
                    html += '<span class="fa fa-star-o"></span>\n'
                rating -= 1.0
            html += ' ' + str(recipe['rating']) + '   (' + str(reviews) + ') user ratings</h5>\n'
        html += '</div><!--/col-sm-4-->\n'
        html += '</div><!--/row-->\n'
        html += '<div class="row">\n'
        html += '<div class="col-sm-8">\n'


    html += '<i class="fa fa-list-ul fa-fw" aria-hidden="true"></i>&nbsp;<strong>Ingredients</strong>\n'
    ingredients = recipe['ingredients']
    if 'section1' in ingredients:
        section = 'section1'
        count = 1
        while section in ingredients:
            html += render_ingredients(ingredients[section])
            count = count + 1
            section = 'section' + str(count)
    else:
        html += render_ingredients(ingredients)
    html += '<i class="fa fa-tasks fa-fw" aria-hidden="true"></i> <strong>Instructions</strong>\n'
    instructions = recipe.get('instructions')
    if 'section1' in instructions:
        section = 'section1'
        count = 1
        while section in instructions:
            html += render_instructions(instructions[section], mode)
            count = count + 1
            section = 'section' + str(count)
    else:
        html += render_instructions(instructions, mode)
    if 'notes' in recipe:
        html += '<i class="fa fa-list-alt fa-fw" aria-hidden="true"></i>&nbsp;<strong>Notes</strong>\n'
        html += '<p>' + recipe['notes'] + '</p>\n'

    return html

class RecipeManager(object):
    """ Recipe Manager
    """

    def __init__(self, config):
        self.config = config
        self.recipes = {}
        self.database = DynamoDB(config, 'Recipes')

    def load_recipes(self, infile):
        """ Load json data for recipes
            [
              {
              "title": "Korean Meatballs",
              "ingredients": {
                "subtitle": "Meatballs",
                "1 1/2 lb": "lean ground turkey",
                "1 tsp": "ground ginger",
                "1/4 tsp": "fresh ground black pepper",
                "2 tsp": "Sambal Oelek or Chili Garlic Sauce",
                "1 tsp": "mesquite seasoning",
                "1/2": "cup Panko",
                "1+ tsp": "garlic salt",
                "1": "egg",
                "3-4": "green onions",

                "subtitle":"Spicy Apricot Glaze",
                "1/2 cup": "apricot jam",
                "2 tsp": "soy sauce",
                "2 tsp": "Srirachi"
              },
              "instructions": [
                "preheat oven to 400 degrees, line baking sheet with parchment",
                "in a large bowl mix meatball ingredients, form into 1\" balls, cook 20-25 minutes",
                "in medium bowl mix glaze ingredients, add meatballs and toss until coated",
                "garnish with chopped chives or green ends of onions",
                "serve over noodles or rice:
              ]
            },
            ...
            ]
        Args:
            file: json file to load
        """
        try:
            with open(infile) as json_file:
                recipes = json.load(json_file)
                for recipe in recipes:
                    if 'title' in recipe and 'ingredients' in recipe and 'instructions' in recipe:
                        recipe_id = generate_id(recipe['title'])
                        print "Loaded " + recipe['title']
                        self.recipes[recipe_id] = recipe
        except (IOError, ValueError) as err:
            print('Load of recipe file failed:', err.message)

    def build_search_list(self, category=None):
        """ Build the quick find search list
        """
        html = ''
        for recipe_id in self.recipes:
            recipe = self.recipes[recipe_id]
            if category is None or category in recipe['category']:
                html += '<li><a href="/recipes?recipe=' + recipe['title'].replace(' ', '%20') + '">' + recipe['title'] + '</a></li>\n'
        return html

    def get_recipe(self, recipe_id):
        """ Load recipe from Database
        Args:
            recipe_id: Database 'id' or title
        Returns:
            dictionary
        """
        if len(recipe_id) == 48 and contains_only(recipe_id, '0123456789ABCDEFGHJKMNPQRSTVWXYZ'):
            return self.database.get_item('id', recipe_id)
        else:
            return self.database.get_item('id', generate_id(recipe_id))

    def save_recipe(self, recipe):
        """ Save recipe in Database
        Args:
            recipe: Dictionary
        Returns:
            dictionary status
        """
        if 'title' in recipe:
            recipe_id = generate_id(recipe['title'])
            recipe['id'] = recipe_id
            return self.database.put_item(recipe)
        else:
            return dict(error='Missing recipe title')

    def get_rendered_recipe(self, recipe_id):
        """ Get HTML rendered recipe
        Args:
            recipe id or title
        Returns:
            HTML for recipe
        """
        if len(recipe_id) != 48 or not contains_only(recipe_id, '0123456789ABCDEFGHJKMNPQRSTVWXYZ'):
            recipe_id = generate_id(recipe_id)
        if recipe_id in self.recipes:
            recipe = self.recipes[recipe_id]
        else:
            recipe = self.get_recipe(recipe_id)

        if recipe is not None and 'error' not in recipe:
            return render_recipe(recipe)

    def get_latest_recipe(self):
        """ Get HTML rendered latest recipe
        Returns:
            HTML for recipe
        """
        latest = 'Cuban Picadillo'
        html = "<p>Search or navigate to the best of our family favorite recipes. You won't find anything with bacon or cream, just healthy and delicious with a tendency towards the spicy side of life. Mild red chili powder can be substituted for the hot stuff or left out entirely in most cases and your favorite hot sauce added at the table.</p>"
        html += '<h4 itemprop="name">' + latest + '</h4>\n'
        html += self.get_rendered_recipe(latest)
        return html

    def find_recipe_by_category(self, category):
        """ Find recipes of the specified category (e.g. 'asian')
        Args:
            category to search for
        Returns:
            list of recipe titles
        """
        matches = []
        for recipe_id in self.recipes:
            recipe = self.recipes[recipe_id]
            if 'category' in recipe and category in recipe['category']:
                matches.append(recipe['title'])
        return matches

    def get_rendered_gallery(self, category=None):
        """ Render an image gallery of recipe pictures
        Args:
            category to match or None for all
        Returns:
            HTML container with image gallery
        """
        html = '<div class="gal">\n'
        for recipe_id in self.recipes:
            recipe = self.recipes[recipe_id]
            if category is None or category in recipe['category']:
                title = recipe['title']
                image = 'https://snowyrangesolutions.com/static/img/' + title.replace(" ", "") + '.jpg'
                link = '/recipes?recipe=' + title.replace(" ", "%20") + '&category=' + recipe['category'][0]
                html += '<a href="' + link + '" title="' + title + '">\n'
                html += '<img src="' + image + '" alt="' + title + '"></a>\n'
        html += '</div>\n'
        return html

def main():
    """ Unit tests
    """
    manager = RecipeManager('noneedtomeasure')
    manager.load_recipes('recipes.json')
    print manager.get_rendered_recipe('Korean Meatballs')
    print manager.get_rendered_recipe('Pumpkin Waffles')
    print manager.get_rendered_recipe('Strawberry Pancakes')
    print manager.get_rendered_recipe('Meatball Marinara')
    print manager.find_recipe_by_category('asian')
    print render_time('prepTime', '20 mins')
    print render_time('prepTime', '20 minutes')
    print render_time('cookTime', '1 hour')
    print render_time('totalTime', '3 hours')
    print render_time('totalTime', '1 hour 20 mins')
    print render_time('totalTime', '1 hour 20 minutes')
    print add_times('45 mins', '1 hour 20 minutes')
    print add_times('45 mins', '25 minutes')
    print add_times('45 mins', '2 hours')
    print manager.get_rendered_gallery()
    print manager.get_rendered_gallery('Asian')

if __name__ == '__main__':
    main()

