from setuptools import setup, find_packages

install_requires = []

with open('requirements.txt') as f:
    for line in f:
        if line.startswith('#'):
            continue
        install_requires.append(line)

classifiers=[
    'Development Status :: 3 - Alpha',
    'License :: MIT License',
    'Programming Language :: Python :: 2.7'
]

keywords = 'networking ports port-scanner lib'

metadata = dict(
    name = "Pyposcn",
    version='0.1',
    description='A port scanner tool and library',
    author='George Karlos',
    author_email='blabla@gmail.com',
    license='MIT',
    url='https://github.com/gkarlos/pyposcn',
    install_requires=install_requires,
    classifiers=classifiers,
    keywords=keywords,
    packages=find_packages()
    )

setup(**metadata)
