from setuptools import setup
from codecs import open
import pathlib

REPO_URL = "http://github.com/MatMaul/pynetgear"
VERSION = "0.8.0"

with open("requirements.txt") as f:
    required = f.read().splitlines()

# The directory containing this file
HERE = pathlib.Path(__file__).parent

# The text of the README file
README = (HERE / "README.md").read_text()

setup(
    name="pynetgear",
    version=VERSION,
    description="Access Netgear routers using their SOAP API",
    long_description=README,
    long_description_content_type="text/markdown",
    url=REPO_URL,
    download_url=REPO_URL + "/tarball/" + VERSION,
    author="Paulus Schoutsen",
    author_email="Paulus@PaulusSchoutsen.nl",
    license="MIT",
    install_requires=required,
    packages=["pynetgear"],
    zip_safe=True,
)
