from setuptools import Extension, setup

try:
    from Cython.Build import cythonize
except Exception as exc:
    raise SystemExit("Cython is required to build bench_native") from exc

extensions = [
    Extension(
        "bench_native",
        ["bench_native.pyx"],
        extra_compile_args=["-pthread"],
        extra_link_args=["-pthread"],
    )
]

setup(
    name="bench_native",
    ext_modules=cythonize(extensions, compiler_directives={"language_level": "3"}),
)
