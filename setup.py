from setuptools import setup, find_packages

setup(
    name="viper-core",
    version="2.0.0",
    author="deva-codex",
    description="Military-grade data sanitization & forensic obliteration suite",
    url="https://github.com/deva-codex/viper",
    license="MIT",
    packages=find_packages(exclude=["tests*"]),
    install_requires=[
        "cryptography>=41.0.0",
        "psutil>=5.9.0",
        "colorama>=0.4.6",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
        ],
    },
    python_requires=">=3.10",
    entry_points={
        "console_scripts": [
            "viper=viper_core.cli:execute_cli",
        ],
    },
)
