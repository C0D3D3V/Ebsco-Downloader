from os import path

from setuptools import find_packages, setup

# Get the version from ebsco_dl/version.py without importing the package
exec(compile(open('ebsco_dl/version.py').read(), 'ebsco_dl/version.py', 'exec'))


def readme():
    this_directory = path.abspath(path.dirname(__file__))
    with open(path.join(this_directory, 'README.md'), encoding='utf-8') as f:
        return f.read()


setup(
    name='ebsco-dl',
    version=__version__,
    description='A tool to download ebooks from EBSCO',
    long_description=readme(),
    long_description_content_type='text/markdown',
    url='https://github.com/user/Ebooks-Downloader',
    author='user',
    author_email=' user@mag-keinen-spam.de',
    license='MIT',
    packages=find_packages(),
    include_package_data=True,
    entry_points={
        'console_scripts': [
            'ebsco-dl = ebsco_dl.main:main',
        ],
    },
    python_requires='>=3.6',
    install_requires=[
        'certifi>=2022.6.15',
        'pycryptodomex>=3.20.0',
        'requests>=2.28.1',
        'colorama>=0.4.6',
        'pypdf>=4.1.0',
        'colorlog>=6.7.0',
        'lxml>=5.1.1',
        'aiohttp>=3.9.3',
        'aiofiles>=23.2.1',
    ],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: End Users/Desktop',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3 :: Only',
        'Topic :: Education',
        'Topic :: Utilities',
    ],
    zip_safe=False,
)
