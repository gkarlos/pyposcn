from setuptools import setup

install_requires = []

with open('requirements.txt') as f:
    for line in f:
        if line.startswith('#'):
            continue
        install_requires.append(line)

metadata = dict(
    name = "Pyposcn",
    version='0.1',
    description='A port scanner tool and API',
    author='George Karlos',
    author_email='blabla@gmail.com',
    license='MIT',
    url='https://github.com/gkarlos/pyposcn',
    install_requires=install_requires

    )

setup(**metadata)
