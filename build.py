from setuptools import setup
from setuptools_rust import Binding, RustExtension

setup(
    name="vanity_search",
    rust_extensions=[RustExtension("vanity_search", binding=Binding.PyO3)],
    zip_safe=False,
) 