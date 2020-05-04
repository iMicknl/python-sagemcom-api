from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="sagemcom_api",
    version="0.1.0",
    author="Mick Vleeshouwer",
    author_email="mick@imick.nl",
    description="Python wrapper to interact with SagemCom F@st routers via internal API's.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/iMicknl/python-sagemcom-api",
    classifiers=(
        'Development Status :: 3 - Alpha',
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ),
    packages=find_packages(),
    install_requires=['aiohttp==3.6.1'],
)
