from setuptools import setup, find_packages

setup(
    name="xssentry",
    version="4.0",
    description="Autonomous XSS Hunter [HELLHOUND-class]",
    author="Hellhound Security",
    packages=find_packages(),
    py_modules=["spider"],
    entry_points={
        "console_scripts": [
            "xssentry=xssentry.main:main",
        ],
    },
    install_requires=[
        "playwright",
        "aiohttp",
        "beautifulsoup4",
        "lxml",
    ],
    python_requires=">=3.7",
)

