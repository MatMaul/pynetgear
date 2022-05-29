from setuptools import setup
from codecs import open

REPO_URL = "http://github.com/MatMaul/pynetgear"
VERSION = "0.10.3"

with open("requirements.txt") as f:
    required = f.read().splitlines()

with open("README.md") as f:
    README = f.read()

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
