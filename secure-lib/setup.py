from setuptools import find_packages, setup

setup(
    name="secure-lib",
    version="0.1.0",
    description="Reusable AI/LLM security components for the OSS AI Security Blueprint",
    author="OSS AI Security Blueprint Contributors",
    python_requires=">=3.9",
    packages=find_packages(),
    install_requires=["regex>=2023.0"],
    extras_require={"dev": ["pytest", "pytest-cov"]},
)
