"""
VCC PKI Client - Setup Configuration
====================================

Install:
    pip install -e client/
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
readme_file = Path(__file__).parent / "README.md"
if readme_file.exists():
    long_description = readme_file.read_text(encoding="utf-8")
else:
    long_description = "VCC PKI Client Library for easy certificate management"

setup(
    name="vcc-pki-client",
    version="1.0.0",
    description="Python client library for VCC PKI Server",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="VCC Team",
    author_email="support@vcc.local",
    url="https://github.com/vcc/pki-client",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        # No hard dependencies - httpx is optional
    ],
    extras_require={
        "httpx": ["httpx>=0.24.0"],
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
            "mypy>=0.990"
        ]
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries :: Python Modules"
    ],
    keywords="pki certificate ssl tls mtls client",
    project_urls={
        "Documentation": "https://github.com/vcc/pki-client/docs",
        "Source": "https://github.com/vcc/pki-client",
        "Tracker": "https://github.com/vcc/pki-client/issues"
    }
)
