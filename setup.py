from setuptools import setup, find_packages

setup(
    name="ddos-predictor",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "pandas",
        "numpy",
        "scikit-learn",
        "xgboost",
        "joblib"
    ],
    entry_points={
        "console_scripts": [
            "ddos-predict=predictor.cli:main"
        ]
    },
    author="Your Name",
    description="A CLI tool to predict DDoS attack types from CSV files using trained ML models",
    include_package_data=True,
)
