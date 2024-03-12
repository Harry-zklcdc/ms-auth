from setuptools import setup, find_packages

setup(
    name='ms_auth',
    version='1.1.6',
    description='Microsoft Login Lib',
    author='Harry-zklcdc',
    author_email='zklcdc@qq.com',
    packages=find_packages(),
    package_data={'ms_auth':['*.so','*.dll']},
    platforms=['linux', 'windows', 'macos'],
    classifiers=[
        'License :: OSI Approved :: GNU Affero General Public License v3',
        'Programming Language :: Python :: 3',
    ],
)