#! /usr/bin/env python
# -*- coding: utf-8 -*-

def input_filter(string):
    joke = "help copyright credits license".split(" ")
    for i in joke:
        if i in string.lower():
            print "All works and no play makes python a dull boy :("
            return ""

    ban = ['exec',
           'eval',
           'pickle',
           'os',
           'timeit',
           'subprocess',
           'popen',
           'input',
           'sys',
           'cat',
           'flag',
           'execve',
           'reload',
           'file',
           'open']
    for i in ban:
        if i in string.lower():
            print 'You shall not input "{}"'.format(i)
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

while 1:
    inp = raw_input('>>> ')
    cmd = input_filter(inp)
    
    try:
        exec cmd
    except Exception,errorinfo:
        print "Error:",
        print errorinfo
