from setuptools import setup
from codecs import open

REPO_URL = "http://github.com/MatMaul/pynetgear"
VERSION = "0.9.1"

with open("requirements.txt") as f:
    required = f.read().splitlines()

setup(
    name="pynetgear",
    version=VERSION,
    description="Access Netgear routers using their SOAP API",
    url=REPO_URL,
    download_url=REPO_URL + "/tarball/" + VERSION,
    author="Paulus Schoutsen",
    author_email="Paulus@PaulusSchoutsen.nl",
    license="MIT",
    install_requires=required,
    packages=["pynetgear"],
    zip_safe=True,
)
