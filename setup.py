from setuptools import setup, find_packages

setup(
    name="certificate-validator",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        "cryptography",
        "pytest",
        "flask",
    ],
    python_requires=">=3.7",
) 