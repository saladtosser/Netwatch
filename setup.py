#!/usr/bin/env python3
"""
NetWatch Enterprise SIEM/IDS/IPS Platform
Setup script for installation and distribution
"""

from setuptools import setup, find_packages
import os

# Read README for long description
def read_readme():
    readme_path = os.path.join(os.path.dirname(__file__), 'README.md')
    if os.path.exists(readme_path):
        with open(readme_path, 'r', encoding='utf-8') as f:
            return f.read()
    return "NetWatch Enterprise SIEM/IDS/IPS Platform"

# Read requirements
def read_requirements():
    req_path = os.path.join(os.path.dirname(__file__), 'requirements.txt')
    if os.path.exists(req_path):
        with open(req_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    return []

setup(
    name="netwatch",
    version="3.0.0",
    author="NetWatch Team",
    author_email="team@netwatch.dev",
    description="Enterprise-grade SIEM/IDS/IPS platform for Linux",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/netwatch/netwatch",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Networking :: Monitoring",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: POSIX :: Linux",
        "Environment :: Console",
        "Environment :: No Input/Output (Daemon)",
    ],
    python_requires=">=3.8",
    install_requires=read_requirements(),
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
            "mypy>=1.0.0",
        ],
        "enterprise": [
            "redis>=4.0.0",
            "kafka-python>=2.0.0",
            "clickhouse-driver>=0.2.0",
            "prometheus-client>=0.15.0",
            "aiohttp>=3.8.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "netwatch=netwatch.agent:main",
            "netwatchctl=netwatch.cli.netwatchctl:main",
        ],
    },
    include_package_data=True,
    package_data={
        "netwatch": [
            "rules/examples/*.yaml",
            "config/*.yaml",
        ],
    },
    data_files=[
        ("/etc/netwatch", ["netwatch.service"]),
        ("/etc/systemd/system", ["netwatch.service"]),
    ],
    keywords=[
        "siem", "ids", "ips", "security", "monitoring", "threat-detection",
        "network-security", "log-analysis", "incident-response", "linux"
    ],
    project_urls={
        "Bug Reports": "https://github.com/netwatch/netwatch/issues",
        "Source": "https://github.com/netwatch/netwatch",
        "Documentation": "https://docs.netwatch.dev",
    },
)

