from setuptools import setup

setup(name='pynetgear',
      version='0.5.0',
      description='Access Netgear routers using their SOAP API',
      url='http://github.com/MatMaul/pynetgear',
      download_url='http://github.com/MatMaul/pynetgear/archive/0.5.0.tar.gz',
      author='Paulus Schoutsen',
      author_email='Paulus@PaulusSchoutsen.nl',
      license='MIT',
      install_requires=['requests>=2.0'],
      packages=['pynetgear'],
      zip_safe=True)
