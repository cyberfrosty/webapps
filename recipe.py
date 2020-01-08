#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2017-2019 Alan Frost, All rights reserved.

Implementation of Recipe manager

"""

from __future__ import print_function
from datetime import datetime
import re
import os
import json

from awsutils import DynamoDB
from utils import generate_id, contains_only, read_csv, compare_dicts

TBSP2CUP = 0.0625
TSP2CUP = 0.020833
latest = ['Rolled Ginger Cookies', 'Chocolate Spice Cookies', 'Egg Yolk Lemon Cookies', 'Lamb Kofta', 'Vietnamese Meatballs', 'Korean Meatball Marinara', 'Parmesan Roasted Brussel Sprouts', 'Whole Wheat Biscuits', 'Cashew Chicken']

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
        if duration % 60 > 0:
            total_time = '{} hours {} minutes'.format(duration / 60, duration % 60)
        else:
            total_time = '{} hours'.format(duration / 60)
    elif duration > 60:
        total_time = '1 hour {} minutes'.format(duration % 60)
    elif duration == 60:
        total_time = '1 hour'
    else:
        total_time = '{} minutes'.format(duration)
    return total_time

def render_nutrition(nutrition):
    """ Render the nutrition entry
    Args:
        nutrition dict
    Returns:
        html string
    """
    html = '<div itemprop="nutrition" itemscope itemtype="http://schema.org/NutritionInformation">\n'
    html += '<i class="fa fa-heart-o fa-fw" aria-hidden="true"></i>'
    if 'calories' in nutrition:
        html += ' <span itemprop="calories">{} calories</span>'.format(nutrition['calories'])
    if 'fat' in nutrition:
        html += ', <span itemprop="fatContent">{}g fat</span>'.format(nutrition['fat'])
    if 'carbohydrate' in nutrition:
        html += ', <span itemprop="carbohydrateContent">{}g carb</span>'.format(nutrition['carbohydrate'])
    if 'protein' in nutrition:
        html += ', <span itemprop="proteinContent">{}g protein</span>'.format(nutrition['protein'])
    if 'sodium' in nutrition:
        html += ', <span itemprop="sodiumContent">{}mg sodium</span>'.format(nutrition['sodium'])
    if 'serving' in nutrition:
        html += ', <span itemprop="servingSIze">{}</span>\n'.format(nutrition['serving'])
    html += '</div>\n'
    return html

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
    html = '<div><meta itemprop="' + time_property + '" content="' + duration + '">'
    html += '<i class="fa fa-clock-o fa-fw" aria-hidden="true"></i>&nbsp;' + time_value + '</div>\n'
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

def get_image_srcset(recipe):
    """ Generate HTML for image srcset
    Args:
        recipe: dictionary
    Returns:
        HTML
    """

    html = ''
    title = recipe['title']
    if 'image' in recipe:
        image, ext = os.path.splitext(recipe['image'])
        if image.endswith('_hd'):
            image = image.replace('_hd', '')
        small = image + '_small' + ext
        medium = image + '_medium' + ext
        large = recipe['image']
    else:
        image = '/img/' + title.replace(' ', '')
        small = image + '_small.jpg'
        medium = image + '_medium.jpg'
        large = image + '.jpg'
    if 'image' in recipe or os.path.isfile('static' + large):
        html = '<img itemprop="image" src="' + large + '" alt="' + title + '" ' \
               'srcset="' + large + ' 1400w,' + medium + ' 768w,' + small + ' 576w" ' \
               'sizes="(max-width: 576px) 500px, (max-width: 768px) 650px, 1400px">\n'
    return html

def render_recipe_summary(recipe, makeit=False):
    """ Render a recipe as HTML
    Args:
        recipe: dictionary
    Returns:
        HTML
    """

    html = '<div class="row recipe">\n'
    html += '<div class="col-sm-6">\n'
    title = recipe['title']
    url = '/recipes?recipe=' + title.replace(' ', '%20')
    if not makeit:
        html += '<meta itemprop="url" content="' + url + '" />\n'
    html += get_image_srcset(recipe)
    html += '</div><!--/col-sm-6-->\n'
    html += '<div class="col-sm-6">\n'
    if 'description' in recipe:
        html += '<div itemprop="description"><i class="fa fa-newspaper-o fa-fw" aria-hidden="true"></i>&nbsp;' + recipe['description'] + '</div>\n'
    if 'chef' in recipe:
        html += '<div itemprop="author"><i class="fa fa-cutlery fa-fw" aria-hidden="true"></i>&nbsp;Chef ' + recipe['chef'] + '</div>\n'
    if 'yield' in recipe:
        yields = recipe['yield']
        if 'Serves' in yields:
            icon = '<i class="fa fa-group fa-fw" aria-hidden="true">'
        else:
            icon = '<i class="fa fa-clone fa-fw" aria-hidden="true">'
        html += '<div itemprop="recipeYield">' + icon + '</i>&nbsp;' + yields + '</div>\n'
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
        html += '<div itemprop="datePublished" content="' + posted + '">'
        html += '<i class="fa fa-calendar fa-fw" aria-hidden="true"></i>&nbsp;' + recipe['date'] + '</div>\n'
    if 'nutrition' in recipe:
        html += render_nutrition(recipe['nutrition'])
    if 'rating' in recipe:
        rating = recipe['rating']
        reviews = 2
        html += '<div itemprop="aggregateRating" itemscope itemtype="http://schema.org/AggregateRating">\n'
        html += '  <meta itemprop="ratingValue" content="' + str(rating) + '">\n'
        html += '  <meta itemprop="reviewCount" content="' + str(reviews) + '">\n'
        for i in range(5):
            if rating > 0.75:
                html += '  <span class="fa fa-star star-checked"></span>\n'
            elif rating > 0.25:
                html += '  <span class="fa fa-star-half-o star-checked"></span>\n'
            else:
                html += '  <span class="fa fa-star-o"></span>\n'
            rating -= 1.0
        html += ' ' + str(recipe['rating']) + '   (' + str(reviews) + ') user ratings\n</div>\n'
    if makeit:
        html += '<a class="btn btn-primary" href="' + url + '" role="button"><i class="fa fa-external-link" aria-hidden="true"></i> Make it</a>\n'
    html += '</div><!--/col-sm-6-->\n'
    html += '</div><!--/row-->\n'
    return html


class RecipeManager(object):
    """ Recipe Manager
    """

    def __init__(self, config):
        self.config = config
        self.recipes = {}
        self.ingredients = {}
        self.references = {}
        self.database = DynamoDB(config, 'Recipes')

    def load_recipes(self, infile):
        """ Load json data for recipes
            [
              { "include": "cookies.json" }
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
                    if 'include' in recipe:
                        self.load_recipes(recipe['include'])
                    elif 'title' in recipe and 'ingredients' in recipe and 'instructions' in recipe:
                        recipe_id = generate_id(recipe['title'])
                        print("Loaded " + recipe['title'])
                        self.recipes[recipe_id] = recipe
        except (IOError, ValueError) as err:
            print('Load of recipe file failed:', err.message)

    def load_references(self, infile):
        """ Load json data for sauces, spice mixtures and other referenced items
        Args:
            file: json file to load
        """
        try:
            with open(infile) as json_file:
                items = json.load(json_file)
                for item in items:
                    if 'include' in item:
                        self.load_references(item['include'])
                    elif 'title' in item and 'ingredients' in item:
                        print("Loaded " + item['title'])
                        self.references[item['title']] = item
        except (IOError, ValueError) as err:
            print('Load of reference file failed:', err.message)


    def load_nutrition(self, csvfile='nutrition.csv'):
        """ Load the CSV file with nutrition information
        """
        nutrition = read_csv(csvfile)
        for ingredient in nutrition:
            self.ingredients[ingredient['item']] = ingredient

    def count_calories(self, title):
        """ Count the nutrition values for a recipe
        """
        recipe = self.get_recipe(title)
        if not recipe or 'error' in recipe:
            print('Recipe not found: {}'.format(title))
            return
        serves, people = recipe.get('yield').split()
        factor = 1.0 / float(people)
        ingredients = recipe.get('ingredients')
        if 'section1' in ingredients:
            nutrition = {'calories': 0.0, 'fat': 0.0, 'carbohydrate': 0.0,
                         'protein': 0.0, 'sodium': 0.0}
            section = 'section1'
            count = 1
            while section in ingredients:
                items = ingredients[section]
                if 'reference' in items:
                    reference = self.references.get(items['reference'])
                    if reference:
                        items = reference.get('ingredients')
                    else:
                        print('Reference {} not found'.format(items['reference']))
                section_nutrition = self.count_nutrition(items, factor)
                nutrition['calories'] += section_nutrition['calories']
                nutrition['fat'] += section_nutrition['fat']
                nutrition['carbohydrate'] += section_nutrition['carbohydrate']
                nutrition['protein'] += section_nutrition['protein']
                nutrition['sodium'] += section_nutrition['sodium']
                count = count + 1
                section = 'section' + str(count)
        else:
            nutrition = self.count_nutrition(ingredients, factor)

        nutrition['calories'] = int(round(nutrition['calories']))
        nutrition['fat'] = int(round(nutrition['fat']))
        nutrition['carbohydrate'] = int(round(nutrition['carbohydrate']))
        nutrition['protein'] = int(round(nutrition['protein']))
        nutrition['sodium'] = int(round(nutrition['sodium']))
        return nutrition

    def count_nutrition(self, ingredients, factor, verbose=False):
        """ Count the nutrition values for a group of ingredients scaled by servings factor
        """
        calories = 0.0
        fat = 0.0
        carbohydrate = 0.0
        protein = 0.0
        sodium = 0.0
        index = 1
        while 'item' + str(index) in ingredients:
            item = ingredients.get('item' + str(index))
            if 'optional' in item.get('ingredient'):
                index += 1
                continue
            measure = item.get('quantity').split()
            name = item.get('ingredient').split(',')[0]
            paren = name.find('(')
            if paren > 1:
                name = name[0:paren-1]
            if len(measure) > 2:
                quantity = float(measure[0])
                measure = measure[1:]
            else:
                quantity = 0.0
            if measure[0] == '1':
                quantity += 1.0
            elif measure[0] == '3/4':
                quantity += 0.75
            elif measure[0] == '2/3':
                quantity += 0.667
            elif measure[0] == '1/2':
                quantity += 0.5
            elif measure[0] == '1/3':
                quantity += 0.333
            elif measure[0] == '1/4':
                quantity += 0.25
            elif measure[0] == '1/8':
                quantity += 0.125
            elif len(measure) > 1 and (measure[1] == 'can' or measure[1] == 'jar'):
                if measure[0] == 'small':
                    quantity *= 0.75  # 6oz can
                elif measure[0] == 'medium':
                    quantity *= 1.75  # 14oz can
                elif measure[0] == 'large':
                    quantity *= 3.5  # 28oz can
                measure[1] = 'cup'
            else:
                quantity += float(measure[0])

            if name not in self.ingredients:
                print(name)
            else:
                ingredient = self.ingredients.get(name)
                serving = ingredient.get('serving')
                if not serving.isdigit():
                    serving, size = serving.split()
                    if len(measure) > 1 and measure[1] != size:
                        if measure[1] == 'tbsp' and size[:3] == 'cup':
                            quantity *= TBSP2CUP
                        elif measure[1] == 'cup' and size == 'tbsp':
                            quantity /= TBSP2CUP
                        elif measure[1] == 'tbsp' and size == 'tsp':
                            quantity *= 3
                        elif measure[1] == 'tsp' and size == 'tbsp':
                            quantity /= 3
                        elif measure[1][:2] == 'lb' and size == 'oz':
                            quantity *= 16
                quantity = quantity / float(serving)
                scale = factor * quantity
                if verbose:
                    print('{} quantity, {} calories, {}'.format(quantity, scale * float(ingredient.get('calories')), name))
                calories += scale * float(ingredient.get('calories'))
                fat += scale * float(ingredient.get('fat'))
                carbohydrate += scale * float(ingredient.get('carbohydrate'))
                protein += scale * float(ingredient.get('protein'))
                sodium += scale * float(ingredient.get('sodium'))
                #print('{} {} {} {} {}'.format(calories, fat, carbohydrate, protein, sodium))
            index += 1
        return {'calories': calories, 'fat': fat, 'carbohydrate': carbohydrate,
                'protein': protein, 'sodium': sodium}

    def check_nutrition(self):
        """ Check the posted nutrition values with freshley calculated ones
        """
        for recipe_id in self.recipes:
            recipe = self.recipes[recipe_id]
            current_nutrition = recipe.get('nutrition')
            calculated_nutrition = self.count_calories(recipe_id)
            if not compare_dicts(current_nutrition, calculated_nutrition):
                print('{} {}'.format(recipe.get('title'), json.dumps(calculated_nutrition)))

    def check_similar(self):
        """ Check that the recipe has similar recipes and that they all exist
        """
        for recipe_id in self.recipes:
            recipe = self.recipes[recipe_id]
            if 'similar' in recipe:
                for item in recipe['similar']:
                    similar = self.get_recipe(item)
                    if not similar or 'title' not in similar:
                        print('{} {} not found'.format(recipe.get('title'), item))
            else:
                print('{} no similar recipes'.format(recipe.get('title')))

    def check_latest(self):
        """ Check that the recipe has similar recipes and that they all exist
        """
        for item in latest:
            recipe = self.get_recipe(item)
            if not recipe or 'title' not in recipe:
                print('Latest {} {} not found'.format(recipe.get('title'), item))

    def build_navigation_list(self):
        """ Build an accordian navigation list
        """
        html = '<div class="sidebar-module-inset">\n'
        html += '<h5><strong><center>Recipe Navigator</center></strong></h5>\n'
        for category in ['Asian', 'Bread', 'Breakfast', 'Dessert', 'Latin', 'Mediterranean', 'Seafood', 'Vegetables']:
            html += '<button class="accordion">{}</button>\n'.format(category)
            html += '<div class="panel">\n'
            titles = []
            for recipe_id in self.recipes:
                recipe = self.recipes[recipe_id]
                if category in recipe['category']:
                    titles.append(recipe['title'])
            titles.sort()
            for title in titles:
                url = '/recipes?recipe={}'.format(title.replace(' ', '%20'))
                html += '  <a href="{}">{}</a><br>\n'.format(url, title)
            html += '</div>\n'
        html += '</div><!--/siderbar-module-inset-->\n'
        return html

    def build_search_list(self, matches=None):
        """ Build the quick find search list
        Args:
            set of recipe titles
        Returns:
            html for quick search list
        """
        html = ''
        titles = []
        if matches:
            for item in matches:
                recipe = self.get_recipe(item)
                titles.append(recipe['title'])
        else:
            for recipe_id in self.recipes:
                recipe = self.recipes[recipe_id]
                titles.append(recipe['title'])
        titles.sort()
        for title in titles:
            url = '/recipes?recipe={}'.format(title.replace(' ', '%20'))
            html += '<li><a href="{}">{}</a></li>\n'.format(url, title)
        return html

    def render_recipe(self, recipe, mode='read'):
        """ Render a recipe as HTML
        Args:
            recipe: dictionary
        Returns:
            HTML
        """

        html = render_recipe_summary(recipe)
        html += '<div class="row">\n'
        html += '<div class="col-sm-6">\n'

        html += '<i class="fa fa-list-ul fa-fw" aria-hidden="true"></i>&nbsp;<strong>Ingredients</strong>\n'
        ingredients = recipe['ingredients']
        if 'section1' in ingredients:
            section = 'section1'
            count = 1
            while section in ingredients:
                items = ingredients[section]
                if 'reference' in items:
                    reference = self.references.get(items['reference'])
                    if reference:
                        items = reference.get('ingredients')
                        items['title'] = reference.get('title')
                html += render_ingredients(items)
                count = count + 1
                section = 'section' + str(count)
        else:
            html += render_ingredients(ingredients)
        html += '</div><!--/col-sm-6-->\n'
        html += '<div class="col-sm-6">\n'
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

        html += '</div><!--/col-sm-6-->\n'
        html += '</div><!--/row-->\n'
        if 'similar' in recipe:
            html += '<hr />\n<h5>Some Related Recipes</h5>\n'
            html += '<div class="gal">\n'
            for item in recipe['similar']:
                similar = self.get_recipe(item)
                title = similar['title']
                html += '<table><tr><td>\n'
                html += '<figure>\n'
                html += '<figcaption>' + title + '</figcaption>\n'
                link = '/recipes?recipe=' + title.replace(" ", "%20")
                html += '<a href="' + link + '" title="' + title + '">\n'
                html += get_image_srcset(similar)
                html += '</figure>\n'
                html += '</td></tr></table>\n'
            html += '</div>\n'
        return html

    def get_recipe(self, recipe_id):
        """ Load recipe from Database
        Args:
            recipe_id: Database 'id' or title
        Returns:
            dictionary
        """
        if len(recipe_id) != 48 or not contains_only(recipe_id, '234567ABCDEFGHIJKLMNOPQRSTUVWXYZ'):
            recipe_id = generate_id(recipe_id)
        if recipe_id in self.recipes:
            recipe = self.recipes[recipe_id]
        else:
            recipe = self.database.get_item('id', recipe_id)
        return recipe

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
        return dict(error='Missing recipe title')

    def get_rendered_recipe(self, recipe_id):
        """ Get HTML rendered recipe
        Args:
            recipe id or title
        Returns:
            HTML for recipe
        """

        recipe = self.get_recipe(recipe_id)
        if recipe is None:
            return {'error': 'recipe not found: ' + recipe_id}
        if 'error' in recipe:
            return recipe
        return self.render_recipe(recipe)

    def get_recipe_list(self, matches):
        """ Get HTML rendered recipe summaries for search match
        Args
            set of recipe titles
        Returns:
            HTML for recipe
        """
        html = ''
        if len(matches) < 3:
            for item in matches:
                html += '<br />\n<h4 class="caption">' + item + '</h4>\n'
                recipe = self.get_recipe(item)
                html += render_recipe_summary(recipe, True)
        else:
            html = '<div class="gal">\n'
            for item in matches:
                recipe = self.get_recipe(item)
                title = recipe['title']
                html += '<table><tr><td>\n'
                html += '<figure>\n'
                html += '<figcaption>' + title + '</figcaption>\n'
                link = '/recipes?recipe=' + title.replace(" ", "%20")
                html += '<a href="' + link + '" title="' + title + '">\n'
                html += get_image_srcset(recipe)
                html += '</figure>\n'
                html += '</td></tr></table>\n'
            html += '</div>\n'
        return html

    def get_sample_recipes(self):
        """ Get HTML rendered recipe summaries for latest postings
        Returns:
            HTML for recipe
        """
        samples = ['Korean Meatballs', 'Durban Chicken Curry', 'Savory Green Beans', 'Blonde Brownies', 'Orange Chicken', 'Apricot Scones']
        html = '<div class="row">\n'
        html += '<div class="col-sm-4">\n'
        html += self.build_navigation_list()
        html += '</div><!--/col-sm-4-->\n'
        html += '<div class="col-sm-8">\n'
        html += self.get_recipe_list(samples)
        html += '</div><!--/col-sm-8-->\n'
        html += '</div><!--/row-->\n'
        return html

    def get_latest_recipe(self):
        """ Get HTML rendered recipe summaries for latest postings
        Returns:
            HTML for recipe
        """
        html = '<div class="row">\n'
        html += '<div class="col-sm-4">\n'
        html += self.build_navigation_list()
        html += '</div><!--/col-sm-4-->\n'
        html += '<div class="col-sm-8">\n'
        html += "<p>Navigate or search by category, title and ingredients. You won't find anything with bacon or cream, just healthy and delicious with a tendency towards the spicy side of life. Mild red chili powder can be substituted for the hot stuff or left out entirely in most cases and your favorite hot sauce added at the table. Recipes are consistant and easy to make. Nutrition information is calculated from USDA database and specific package labels.</p>\n"
        html += '<h4 class="caption">USDA 2000 calorie diet recommendations</h4>\n'
        html += '<table>\n<tr><th></th><th>Calories</th><th>Fat (g)</th><th>Carbohydrate</th><th>Protein</th><th>Sodium (mg)</th><th>Fiber (g)</th></tr>\n'
        #html += '<tr><th>Female</th><td>1800</td><td>20-35</td><td>130</td><td>46</td><td>1300-2300</td><td>21</td></tr>\n'
        #html += '<tr><th>Male</th><td>2300</td><td>20-35</td><td>130</td><td>56</td><td>1300-2300</td><td>30</td></tr>\n'
        html += '<tr><th>%DV</th><td>2000</td><td>&lt; 65</td><td>300</td><td>50</td><td>&lt; 2300</td><td>&gt; 25</td></tr></table>\n'
        html += '</div><!--/col-sm-8-->\n'
        html += '</div><!--/row-->\n'
        for item in latest:
            html += '<br />\n<h4 class="caption">' + item + '</h4>\n'
            recipe = self.get_recipe(item)
            html += render_recipe_summary(recipe, True)
        return html

    def match_recipe_by_category(self, phrase):
        """ Find recipes that match the phrase in their categories (e.g. 'veg')
        Args:
            phrase to search for
        Returns:
            list of recipe titles
        """
        matches = set()
        for recipe_id in self.recipes:
            recipe = self.recipes[recipe_id]
            for item in recipe.get('category'):
                if re.search(phrase, item, re.IGNORECASE):
                    matches.add(recipe['title'])
                    break
        return matches

    def match_recipe_by_title(self, phrase):
        """ Find recipes that match the phrase in their title (e.g. 'Thai')
        Args:
            phrase to search for
        Returns:
            list of recipe titles
        """
        matches = set()
        for recipe_id in self.recipes:
            recipe = self.recipes[recipe_id]
            words = recipe.get('title').split()
            for word in words:
                if re.search(phrase, word, re.IGNORECASE):
                    matches.add(recipe['title'])
                    break
        return matches

    def match_reference_by_category(self, phrase):
        """ Find references that match the phrase in their categories (e.g. 'Yogurt')
        Args:
            phrase to search for
        Returns:
            list of reference titles
        """
        matches = set()
        for reference_id in self.references:
            reference = self.references[reference_id]
            for item in reference.get('category'):
                if re.search(phrase, item, re.IGNORECASE):
                    matches.add(reference['title'])
                    break
        return matches

    def match_reference_by_title(self, phrase):
        """ Find references that match the phrase in their title (e.g. 'Lime')
        Args:
            phrase to search for
        Returns:
            list of reference titles
        """
        matches = set()
        for reference_id in self.references:
            reference = self.references[reference_id]
            words = reference.get('title').split()
            for word in words:
                if re.search(phrase, word, re.IGNORECASE):
                    matches.add(reference['title'])
                    break
        return matches

    def get_rendered_gallery(self, matches=None):
        """ Render an image gallery of recipe pictures
        Args:
            set of titles
        Returns:
            HTML container with image gallery
        """
        if matches:
            html = self.get_recipe_list(matches)
        else:
            html = '<div class="gal">\n'
            for recipe_id in self.recipes:
                recipe = self.recipes[recipe_id]
                title = recipe['title']
                html += '<table><tr><td>\n'
                html += '<figure>\n'
                html += '<figcaption>' + title + '</figcaption>\n'
                link = '/recipes?recipe=' + title.replace(" ", "%20")
                html += '<a href="' + link + '" title="' + title + '">\n'
                html += get_image_srcset(recipe)
                html += '</figure>\n'
                html += '</td></tr></table>\n'
            html += '</div>\n'
        return html

def main():
    """ Unit tests
    """
    manager = RecipeManager('noneedtomeasure')
    manager.load_references('sauces.json')
    manager.load_references('spices.json')
    manager.load_recipes('recipes.json')
    manager.load_nutrition('nutrition.csv')
    print(manager.match_recipe_by_category('asian'))
    print(manager.match_recipe_by_category('turk'))
    print(manager.match_recipe_by_title('thai'))
    veggies = manager.match_recipe_by_category('veg')
    med = manager.match_recipe_by_category('med')
    print(veggies.union(med))
    print(manager.match_reference_by_category('yog'))
    print(manager.match_reference_by_title('ranch'))

    print(render_time('prepTime', '20 mins'))
    print(render_time('prepTime', '20 minutes'))
    print(render_time('cookTime', '1 hour'))
    print(render_time('totalTime', '3 hours'))
    print(render_time('totalTime', '1 hour 20 mins'))
    print(render_time('totalTime', '1 hour 20 minutes'))
    print(add_times('45 mins', '1 hour 20 minutes'))
    print(add_times('45 mins', '25 minutes'))
    print(add_times('45 mins', '2 hours'))
    print(add_times('20 mins', '40 minutes'))
    print(add_times('60 mins', '2 hours'))
    #print(manager.get_rendered_gallery())
    #print(manager.get_rendered_gallery('Asian'))
    #print(json.dumps(manager.count_calories('French Bread')))
    manager.check_nutrition()
    manager.check_similar()
    manager.check_latest()

if __name__ == '__main__':
    main()
