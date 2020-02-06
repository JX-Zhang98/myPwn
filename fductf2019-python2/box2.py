#! /usr/bin/env python
# -*- coding: utf-8 -*-

from cpython import get_dict
from types import FunctionType

def delete_type():
    type_dict = get_dict(type)
    del type_dict['__bases__']
    del type_dict['__subclasses__']

def delete_func_code():
    func_dict = get_dict(FunctionType)
    del func_dict['func_code']
    del func_dict['__closure__']

def builtins_clear():
    blackList = ['open',
                 'file',
                 'eval',
                 'execfile',
                 'compile',
                 '__import__',
                 'input']
    for mod in __builtins__.__dict__.keys():
        if mod in blackList:
            del __builtins__.__dict__[mod]

def input_filter(string):
    joke = "help copyright credits license".split(" ")
    for i in joke:
        if i in string.lower():
            print "All works and no play makes python a dull boy :("
            return ""
    return string

print """
 _____ ____  _   _  ____ _____ _____ 
|  ___|  _ \| | | |/ ___|_   _|  ___|
| |_  | | | | | | | |     | | | |_   
|  _| | |_| | |_| | |___  | | |  _|  
|_|   |____/ \___/ \____| |_| |_|    

Escape from the dark house built with python :)
You have only 60 seconds!
Try to find the flag!

-----------------------------------------------
Python 2.7.15+ (default, Jan 1 2077, 00:00:00)
[GCC 7.4.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
"""[1:-1]

delete_type();del delete_type
delete_func_code();del delete_func_code
builtins_clear();del builtins_clear

del get_dict,FunctionType
del __doc__, __file__, __name__, __package__

while 1:
    inp = raw_input('>>> ')
    cmd = input_filter(inp)
    try:
        exec cmd 
    except Exception, exception_error:
        print "Error:",
        print exception_error
