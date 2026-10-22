from setuptools import setup, find_packages

setup(
    name="xssentry",
    version="5.0.0",
    description="AI-Powered Autonomous XSS Hunter [HELLHOUND-class]",
    long_description="XSSentry v5 — Agentic XSS testing with NVIDIA NIM (Nemotron) AI brain",
    author="Hellhound Security",
    packages=find_packages(),
    py_modules=["xssentry_legacy", "spider_legacy"],
    package_data={
        "xssentry": ["web/*", "web/**/*"],
    },
    include_package_data=True,
    entry_points={
        "console_scripts": [
            "xssentry=xssentry.cli:main",
            "xssentry-app=xssentry_app:main",
            "xssentry-desktop=xssentry_desktop:main",
        ],
    },
    install_requires=[
        "openai>=1.0.0",
        "requests",
        "beautifulsoup4",
        "lxml",
        "rich",
        "aiohttp",
    ],
    python_requires=">=3.9",
)
