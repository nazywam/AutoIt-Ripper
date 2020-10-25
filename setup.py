import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="autoit-ripper", # Replace with your own username
    version="1.0.0",
    author="nazywam",
    author_email="nazywam@gmail.com",
    description="Extract AutoIt scripts embedded in PE binaries",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/nazywam/AutoIt-Ripper",
    packages=setuptools.find_packages(),
    install_requires=open("requirements.txt").read().splitlines(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)