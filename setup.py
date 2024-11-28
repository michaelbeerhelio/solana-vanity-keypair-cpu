from setuptools import setup
from setuptools_rust import Binding, RustExtension

setup(
    name="vanity_search",
    version="0.1.0",
    rust_extensions=[RustExtension("vanity_search", binding=Binding.PyO3)],
    packages=["vanity_search"],
    zip_safe=False,
) 