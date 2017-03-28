#! /usr/bin/env python2.7

from setuptools import setup
from pip.req import parse_requirements


setup(
    name="autofocus",
    packages=['autofocus'],
    version='1.1.5',
    description='AutoFocus Client Lib',
    author='Ben Small, Pat Litke, Russ Holloway, GSRT',
    author_email='gsrt-tech@paloaltonetworks.com',
    url='https://github.com/PaloAltoNetworks-BD/autofocus-client-library/',
    classifiers=['Development Status :: 4 - Beta'],
    install_requires=[str(r.req) for r in parse_requirements("./requirements.txt", session=False)]
)
