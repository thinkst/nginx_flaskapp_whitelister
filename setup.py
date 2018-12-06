from setuptools import setup

setup(
    name='nginx_flaskapp_whitelister',
    description='A tool for whitelisting only endpoints explicitly allowed/defined in a Flask application, when being served by Nginx',
    version='0.1',
    author='Thinkst Applied Research',
    author_email='info@thinkst.com',
    py_modules=['nginx_flaskapp_whitelister'],
    install_requires=[
        'python-nginx>=1.5.1'
      ],
    entry_points = {
        'console_scripts': ['nginx_flaskapp_whitelister=nginx_flaskapp_whitelister:main'],
    },
    license ='3-Clause BSD'
)