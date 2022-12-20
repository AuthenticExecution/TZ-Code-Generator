import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r") as f:
    requirements = f.readlines()

setuptools.setup(
    name="tz-codegen",
    version="0.4.0",
    author="Sepideh Pouyanrad",
    description="Trustzone module code generator for the Authentic Execution framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=setuptools.find_packages(),
    install_requires=requirements,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires='>=3.6',
    entry_points={
        'console_scripts': ['tz-codegen = tzcodegen.generator:__main']
    },
    include_package_data=True,
)
