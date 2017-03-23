#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2017 Alan Frost, All rights reserved.

Implementation of Recipe manage

"""

import simplejson as json

#from awsutils import DynamoDB
#RECIPES = DynamoDB('Recipes')

class RecipeManager(object):
    """ Recipe Manager
    """

    def __init__(self, website):
        self.website = website
        self.recipes = {}

    def load_recipe(self, infile):
        """ Load json data for a recipe
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
                "preheat over to 400, line baking sheet with parchment",
                "in a large bowl mix meatball ingredients, form into 1\" balls, cook for 20-25 minutes",
                "meanwhile in medium bowl mix glaze ingredients, add meatballs and toss until coated",
                "garnish with chopped chives or green ends of onions",
                "serve over noodles or rice:
              ]
            }
        Args:
            file: json file to load
        """
        try:
            with open(infile) as json_file:
                recipe = json.load(json_file)
                if 'title' in recipe and 'ingredients' in recipe and 'instructions' in recipe:
                    html = self.render_recipe(recipe)
                    if html is not None:
                        print "Loaded " + recipe['title']
                        return html
        except IOError:
            print 'Load of recipe failed: ' + infile

    def get_recipe(self, recipe_id):
        """ Load json data for a recipe
        """

    def render_ingredients(self, ingredients):
        if 'title' in ingredients:
            html = '<h5>' + ingredients['title'] + '</h5>\n<ul>\n'

        index = 1
        while 'item' + str(index) in ingredients:
            item = ingredients.get('item' + str(index))
            quantity = item.get('quantity')
            quantity = quantity.replace('1/8', '&#x215B;')
            quantity = quantity.replace('1/4', '&frac14;')
            quantity = quantity.replace('1/2', '&frac12;')
            quantity = quantity.replace('3/4', '&frac34;')
            quantity = quantity.replace('1/3', '&#x2153;')
            quantity = quantity.replace('2/3', '&#x2154;')
            html += '  <li>' + quantity + ' ' + item.get('ingredient') + '</li>\n'
            index += 1

        html += '</ul>\n'
        return html

    def render_recipe(self, recipe, mode='read'):
        """ Render a recipe as HTML
        Args:
            recipe: dictionary
        Returns:
            HTML
        """

        if 'title' in recipe:
            html = '<h4>' + recipe['title'] + '</h4>\n'
        html += '<h5><i class="fa fa-snowflake-o" aria-hidden="true"></i> Ingredients</h5>\n'
        ingredients = recipe['ingredients']
        if 'section1' in ingredients:
            html += self.render_ingredients(ingredients['section1'])
            if 'section2' in ingredients:
                html += self.render_ingredients(ingredients['section2'])
        else:
            html += self.render_ingredients(ingredients)
        html += '<h5><i class="fa fa-snowflake-o" aria-hidden="true"></i> Instructions</h5>\n'
        if mode == 'make':
            html+= '<ol>\n'
        else:
            html+= '<p>\n'
        index = 1
        instructions = recipe.get('instructions')
        while 'step' + str(index) in instructions:
            item = instructions.get('step' + str(index))
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

def main():
    """ Unit tests
    """
    manager = RecipeManager('noneedtomeasure')
    manager.load_recipe('recipes.json')

if __name__ == '__main__':
    main()

