"""Legacy editable-install shim.

Modern pip reads pyproject.toml and uses setuptools' PEP 660 hook. Some distro
pip builds mis-detect that hook in an isolated environment. This file gives
those builds the documented fallback path without changing runtime behavior.
All metadata is duplicated here so setuptools versions that predate PEP 621
can still build the project.
"""

from pathlib import Path

from setuptools import find_packages, setup

README = Path(__file__).with_name("README.md").read_text(encoding="utf-8")

setup(
    name="proveit",
    version="1.0.0",
    description="Claim receipts for AI coding agents: deterministic, LLM-free evidence compilation",
    long_description=README,
    long_description_content_type="text/markdown",
    license="MIT",
    python_requires=">=3.9",
    packages=find_packages(include=["proveit", "proveit.*"]),
    install_requires=[],
    extras_require={"test": ["pytest>=7"]},
    entry_points={"console_scripts": ["proveit = proveit.cli:main"]},
    keywords=["ai-agents", "verification", "provenance", "ci", "developer-tools"],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Topic :: Software Development :: Quality Assurance",
    ],
)
