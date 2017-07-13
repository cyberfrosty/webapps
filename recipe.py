#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2017 Alan Frost, All rights reserved.

Implementation of Recipe manage

"""

import simplejson as json

from awsutils import DynamoDB
from utils import generate_user_id, contains_only

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
                "preheat over to 400, line baking sheet with parchment",
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
                        recipe_id = generate_user_id(recipe['title'])
                        print "Loaded " + recipe['title']
                        self.recipes[recipe_id] = recipe
        except (IOError, ValueError) as err:
            print('Load of recipe file failed:', err.message)

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
            return self.database.get_item('id', generate_user_id(recipe_id))

    def save_recipe(self, recipe):
        """ Save recipe in Database
        Args:
            recipe: Dictionary
        Returns:
            dictionary status
        """
        if 'title' in recipe:
            recipe_id = generate_user_id(recipe['title'])
            recipe['id'] = recipe_id
            return self.database.put_item(recipe)
        else:
            return dict(error='Missing recipe title')

    def render_ingredients(self, ingredients):
        """ Render recipe ingredients as HTML
        Args:
            ingredients: dictionary
        Returns:
            HTML
        """

        if 'title' in ingredients:
            html = '<h5>' + ingredients['title'] + '</h5>\n<ul>\n'
        else:
            html = '<ul>\n'

        index = 1
        while 'item' + str(index) in ingredients:
            item = ingredients.get('item' + str(index))
            quantity = item.get('quantity')
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
        html += '<h5><i class="fa fa-list-ul" aria-hidden="true"></i> Ingredients</h5>\n'
        ingredients = recipe['ingredients']
        if 'section1' in ingredients:
            html += self.render_ingredients(ingredients['section1'])
            if 'section2' in ingredients:
                html += self.render_ingredients(ingredients['section2'])
            if 'section3' in ingredients:
                html += self.render_ingredients(ingredients['section3'])
        else:
            html += self.render_ingredients(ingredients)
        html += '<h5><i class="fa fa-tasks" aria-hidden="true"></i> Instructions</h5>\n'
        if mode == 'make':
            html += '<ol>\n'
        else:
            html += '<p>\n'
        index = 1
        instructions = recipe.get('instructions')
        while 'step' + str(index) in instructions:
            item = instructions.get('step' + str(index))
            item = item.replace('degrees', '&#8457;')
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

    def get_rendered_recipe(self, recipe_id):
        """ Get HTML rendered recipe
        Args:
            recipe id or title
        Returns:
            HTML for recipe
        """
        if len(recipe_id) != 48 or not contains_only(recipe_id, '0123456789ABCDEFGHJKMNPQRSTVWXYZ'):
            recipe_id = generate_user_id(recipe_id)
        if recipe_id in self.recipes:
            recipe = self.recipes[recipe_id]
        else:
            recipe = self.get_recipe(recipe_id)

        if recipe is not None:
            return self.render_recipe(recipe)

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

if __name__ == '__main__':
    main()

