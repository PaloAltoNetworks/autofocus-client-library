#! /usr/bin/env python3

from setuptools import setup, find_packages
from distutils.util import convert_path

main_ns = {}
ver_path = convert_path("autofocus/version.py")
with open(ver_path) as ver_file:
    exec(ver_file.read(), main_ns)

setup(
    name             = "autofocus-client-library",
    packages         = find_packages(exclude=["tests"]),
    version          = main_ns["__version__"],
    description      = "AutoFocus Client Lib",
    author           = "GSRT Tech",
    author_email     = "gsrt-tech@paloaltonetworks.com",
    url              = "https://github.com/PaloAltoNetworks-BD/autofocus-client-library/",
    classifiers      = ["Development Status :: 4 - Beta"],
    python_requires  = ">=3.6",
    install_requires = ['requests', 'aiohttp'],
)
