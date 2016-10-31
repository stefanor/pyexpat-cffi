from setuptools import setup

setup(
    name='pyexpat-cffi',
    author='Stefano Rivera',
    author_email='stefano@rivera.za.net',
    url='https://github.com/stefanor/pyexpat-cffi',
    setup_requires=["cffi>=1.0.0"],
    cffi_modules=["pyexpat/expat_build.py:ffibuilder"],
    packages=['pyexpat'],
    install_requires=["cffi>=1.0.0"],
)
