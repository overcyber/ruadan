import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(
    name='Ruadan',
    version='0.50',
    py_modules=['Ruadan2'],
    packages=['uteis'],
    url='https://github.com/overcyber/ruadan',
    license='MIT',
    author='Austin Scott - changes by Overcyber',
    author_email='',
    description='Ruadan is Kali Linux based Enumeration Orchestrator.  leverages the opensource enumeration tools on Kali to perform multiple active information gathering phases. '
)
