#! /usr/bin/env python2.7

from setuptools import setup
from distutils.util import convert_path

main_ns = {}
ver_path = convert_path('autofocus/version.py')
with open(ver_path) as ver_file:
    exec(ver_file.read(), main_ns)

setup(

    name            =   "AutofocusClientLibrary",
    packages        =   ['autofocus'],
    version         =   main_ns['__version__'],
    description     =   'AutoFocus Client Lib',
    author          =   'Ben Small, Pat Litke, Russ Holloway, GSRT',
    author_email    =   'gsrt-tech@paloaltonetworks.com',
    url             =   'https://github.com/PaloAltoNetworks-BD/autofocus-client-library/',
    classifiers     =   ['Development Status :: 4 - Beta']
)
