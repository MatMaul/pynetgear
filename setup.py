from setuptools import setup

setup(name='pynetgear',
      version='0.3.1',
      description='Access Netgear routers using their SOAP API',
      url='http://github.com/balloob/pynetgear',
      author='Paulus Schoutsen',
      author_email='Paulus@PaulusSchoutsen.nl',
      license='MIT',
      install_requires=['requests>=2.0'],
      packages=['pynetgear'],
      zip_safe=True)
