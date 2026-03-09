from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="lcsajdump",
    version="1.1.2.1", 
    author="Chris1sFlaggin",
    author_email="lcsajdump@chris1sflaggin.it",
    description="A Graph-Based ROP Gadget Finder for RISC-V architectures",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://chris1sflaggin.it/LCSAJdump/",
    
    packages=find_packages(exclude=[
        "testCTFs*",       
        "unitTest*",       
        "_images*",        
        "build*",          
        "dist*",           
        "venv*",           
        "lcsajdump.venv*"  
    ]),
    
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Environment :: Console",
    ],
    python_requires='>=3.6',
    install_requires=[
        "capstone",
        "pyelftools",
        "networkx",
        "click",
        "regex",
    ],
    entry_points={
        'console_scripts': [
            'lcsajdump=lcsajdump.cli:main',
        ],
    },
)
