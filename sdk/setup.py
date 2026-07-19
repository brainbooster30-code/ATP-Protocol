"""
ATP SDK v1.7 — Easy-to-use Python SDK for the Agent Transfer Protocol.

This package wraps the ATP v1.7 protocol implementation into a clean,
high-level API for building federated AI-agent networks.

pip install -e .
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="atp-sdk",
    version="1.7",
    author="ATP SDK Contributors",
    description="Easy-to-use Python SDK for the Agent Transfer Protocol v1.7",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/nousresearch/atp",
    packages=find_packages(include=["atp_sdk", "atp_sdk.*"]),
    python_requires=">=3.10",
    install_requires=[
        "aiohttp>=3.8",
        "blake3>=0.3",
        "cbor2>=5.4",
        "cryptography>=41.0",
    ],
    extras_require={
        "tunnel": ["pyngrok>=7.0", "miniupnpc>=2.0"],  # zero-config tunnel
        "dashboard": ["PySide6>=6.5", "matplotlib>=3.7"],
        "all": [
            "aiohttp>=3.8",
            "blake3>=0.3",
            "cbor2>=5.4",
            "cryptography>=41.0",
            "PySide6>=6.5",
            "matplotlib>=3.7",
            "pyngrok>=7.0",
            "miniupnpc>=2.0",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Security :: Cryptography",
    ],
    keywords="atp, agent transfer protocol, deepseek, ai agents, cryptography, mcc",
)
