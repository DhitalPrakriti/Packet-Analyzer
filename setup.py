from setuptools import setup, find_packages

setup(
    name="packetanalyzer",
    version="1.0.0",
    description="A professional network packet analyzer for educational purposes",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "scapy>=2.4.5",
        "rich>=13.0.0",
        "colorama>=0.4.6",
    ],
    entry_points={
        'console_scripts': [
            'packetanalyzer=cli:main',
        ],
    },
    python_requires=">=3.8",
)