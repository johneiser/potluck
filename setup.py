#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from setuptools import setup
import os

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "potluck",
    version = read("VERSION"),
    license = "gpl-3.0",
    description = "Custom debugger combining dynamic instrumentation with symbolic execution",
    long_description = read("README.md"),
    long_description_content_type = "text/markdown",
    autho = "johneiser",
    url = "https://github.com/johneiser/potluck",
    packages = [
        "potluck",
    ],
    package_data = {
        "potluck": [
            "*.js",
        ],
    },
    include_package_data = True,
    python_requires = ">=3.5.0",
    install_requires = [
        "frida",
    ],
    extras_require = {
        "angr": [
            "angr",
        ],
        "pretty": [
            "prettytable",
        ],
    },
    classifiers = [
        "Development Status :: 3 - Alpha",
        # "Development Status :: 4 - Beta",
        # "Development Status :: 5 - Production / Stable",

        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
    ],
    entry_points = {
        "console_scripts" : [
            "potluck=potluck.__main__:main",
        ],
    },
)

