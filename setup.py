from os import path
from setuptools import setup, find_packages


# Get the version from ebsco_dl/version.py without importing the package
exec(compile(open('ebsco_dl/version.py').read(), 'ebsco_dl/version.py', 'exec'))


def readme():
    this_directory = path.abspath(path.dirname(__file__))
    with open(path.join(this_directory, 'README.md'), encoding='utf-8') as f:
        return f.read()


setup(
    name='ebsco-dl',
    version=__version__,
    description='A collection of tools to download eboks',
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
        'aiohttp>=3.8.1',
        'certifi>=2022.6.15',
        'colorama>=0.4.5',
        'yt-dlp>=2022.6.29',
        'lxml>=4.9.1',
        'aiofiles>=0.6.0',
        'pycryptodome>=3.15.0',
        'rarfile>=4.0',
        'requests>2.28.1',
    ],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: End Users/Desktop',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Programming Language :: Python :: 3 :: Only',
        'Topic :: Education',
        'Topic :: Internet :: WWW/HTTP :: Indexing/Search',
        'Topic :: Multimedia :: Video',
        'Topic :: Multimedia :: Sound/Audio',
        'Topic :: Utilities',
    ],
    zip_safe=False,
)
