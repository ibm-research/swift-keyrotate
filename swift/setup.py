# -*- encoding: utf-8 -*-
name = 'swiftkeyrotate'
keymaster_name = 'rotating_keymaster'
keymaster_entry_point = '%s.rotating_keymaster:filter_factory' % (name)
encryption_name = 'rotating_encryption'
encryption_entry_point = '%s:filter_factory' % (name)
version = '0.1'

from setuptools import setup, find_packages

setup(
    name=name,
    version=version,
    packages=find_packages(),
    install_requires=['swift'],
    entry_points={
        'paste.filter_factory': [
            '%s=%s' % (keymaster_name, keymaster_entry_point),
            '%s=%s' % (encryption_name, encryption_entry_point)
        ]
    },
)
