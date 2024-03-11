from setuptools import setup, find_packages

setup(
    name='ms_auth',
    version='1.0.0',
    description='Microsoft Login Lib',
    author='Harry-zklcdc',
    author_email='zklcdc@qq.com',
    packages=find_packages(),
    package_data={'ms_auth':['*.so','*.dll']},
    platforms=['linux', 'windows', 'macos'],
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: AGPL-3.0',
        'Programming Language :: Python :: 3',
    ],
)