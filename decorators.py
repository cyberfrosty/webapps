#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2017 Alan Frost, All rights reserved.

Decorator utilities

"""
from threading import Thread

def async(func):
    """ Decorator to run function aysychronously
    Args:
        func: function to run
        kwargs: argument for function call
    """
    def wrapper(*args, **kwargs):
        thr = Thread(target=func, args=args, kwargs=kwargs)
        thr.start()
    return wrapper
