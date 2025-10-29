"""Setup script for vcc-pki package

Legacy setup.py for backward compatibility.
Modern packaging uses pyproject.toml.
"""

from setuptools import setup, find_packages
import os

# Read README
here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, "README.md"), "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read version
about = {}
with open(os.path.join(here, "vcc_pki", "__version__.py"), "r", encoding="utf-8") as f:
    exec(f.read(), about)

setup(
    name="vcc-pki",
    version=about["__version__"],
    author=about["__author__"],
    author_email="info@vcc.local",
    description=about["__description__"],
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/covina/vcc-pki",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security :: Cryptography",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
    ],
    python_requires=">=3.10",
    install_requires=[
        "cryptography>=41.0.0",
        "sigstore>=2.0.0",
        "tuf>=3.0.0",
        "click>=8.1.0",
        "pyyaml>=6.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "pytest-asyncio>=0.21.0",
            "black>=23.0.0",
            "mypy>=1.5.0",
            "ruff>=0.0.292",
        ],
        "api": [
            "fastapi>=0.100.0",
            "uvicorn[standard]>=0.23.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "vcc-pki=vcc_pki.api.cli:main",
        ],
    },
)
