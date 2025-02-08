from setuptools import find_packages, setup

classifiers = [
    "Development Status :: 5 - Production/Stable",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: MIT License",
    "Operating System :: OS Independent",
    "Programming Language :: Python",
    "Programming Language :: Python :: 3.8",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Programming Language :: Python :: 3.13",
    "Programming Language :: Python :: Implementation :: CPython",
    "Programming Language :: Python :: Implementation :: PyPy",
    "Topic :: Security :: Cryptography",
    "Topic :: Software Development :: Libraries :: Python Modules",
]

if __name__ == "__main__":

    with open("README.rst", "r", encoding="utf-8") as f:
        readme = f.read()

    setup(
        name="pyemv",
        version="1.5.0",
        author="Konstantin Novichikhin",
        author_email="konstantin.novichikhin@gmail.com",
        description="A Python package for EMV cryptography in payment systems",
        long_description=readme,
        long_description_content_type="text/x-rst",
        license="MIT",
        url="https://github.com/knovichikhin/pyemv",
        packages=find_packages(exclude=["tests"]),
        package_data={"pyemv": ["py.typed"]},
        zip_safe=False,
        install_requires=[
            "cryptography >= 2.8",
        ],
        classifiers=classifiers,
        python_requires=">=3.8",
        keywords="emv arqc arpc tc aac smi smc cvc3 tlv",
    )
