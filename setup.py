from setuptools import setup, find_packages
from pyemv import __version__

classifiers = [
    "Development Status :: 5 - Production/Stable",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: MIT License",
    "Operating System :: OS Independent",
    "Programming Language :: Python",
    "Programming Language :: Python :: 3.5",
    "Programming Language :: Python :: 3.6",
    "Programming Language :: Python :: 3.7",
    "Programming Language :: Python :: 3.8",
    "Programming Language :: Python :: Implementation :: CPython",
    "Programming Language :: Python :: Implementation :: PyPy",
]

if __name__ == "__main__":

    with open("README.rst", "r", encoding="utf-8") as f:
        readme = f.read()

    setup(
        name="pyemv",
        version=__version__,
        author="Konstantin Novichikhin",
        author_email="konstantin.novichikhin@gmail.com",
        description="A Python package for EMV cryptography in payment systems",
        long_description=readme,
        long_description_content_type="text/x-rst",
        license="MIT",
        url="https://github.com/manoutoftime/pyemv",
        packages=find_packages(exclude=["tests"]),
        install_requires=["cryptography >= 2.8",],
        classifiers=classifiers,
        python_requires=">=3.5",
        keywords="emv arqc arpc",
    )
