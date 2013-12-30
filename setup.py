#!/usr/bin/env python

from distutils.core import setup, Extension

setup(name='Blowfish Module',
      version='0.1',
      description='Blowfish',
      author='',
      author_email='blueflycn@gmail.com',
      url='',
      packages=['blowfish'],
      ext_modules=[Extension("blowfish/_blowfish",
                              ["src/py_blowfish.c",
                               "src/blowfish.c"
                               ],
                              libraries=["m"])]
	)
