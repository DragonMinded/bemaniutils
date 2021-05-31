import os
from setuptools import setup


def extensions():
    if 'PURE_PYTHON' in os.environ:
        # We've been asked not to compile extensions.
        return []

    from setuptools import Extension
    from Cython.Build import cythonize

    return [
        *cythonize(
            [
                Extension(
                    "bemani.protocol.binary",
                    [
                        "bemani/protocol/binary.py",
                    ]
                ),
                Extension(
                    "bemani.protocol.lz77",
                    [
                        "bemani/protocol/lz77.py",
                    ]
                ),
                Extension(
                    "bemani.protocol.lz77cpp",
                    [
                        "bemani/protocol/lz77cpp.cxx",
                    ],
                    language="c++",
                    extra_compile_args=["-std=c++14"],
                    extra_link_args=["-std=c++14"],
                ),
                Extension(
                    "bemani.protocol.node",
                    [
                        "bemani/protocol/node.py",
                    ]
                ),
                Extension(
                    "bemani.protocol.protocol",
                    [
                        "bemani/protocol/protocol.py",
                    ]
                ),
                Extension(
                    "bemani.protocol.stream",
                    [
                        "bemani/protocol/stream.py",
                    ]
                ),
                Extension(
                    "bemani.protocol.xml",
                    [
                        "bemani/protocol/xml.py",
                    ]
                ),
                Extension(
                    "bemani.format.afp.blend.blend",
                    [
                        "bemani/format/afp/blend/blend.py",
                    ]
                ),
                Extension(
                    "bemani.format.afp.blend.blendcpp",
                    [
                        "bemani/format/afp/blend/blendcpp.pyx",
                        "bemani/format/afp/blend/blendcppimpl.cxx",
                    ],
                    language="c++",
                    extra_compile_args=["-std=c++14"],
                    extra_link_args=["-std=c++14"],
                ),
                Extension(
                    "bemani.format.afp.types.generic",
                    [
                        "bemani/format/afp/types/generic.py",
                    ]
                ),
                Extension(
                    "bemani.format.dxt",
                    [
                        "bemani/format/dxt.py",
                    ]
                ),
            ],
            language_level=3,
        ),
    ]


setup(
    name='bemani',
    version='1.0',
    description='Code and utilities for talking to BEMANI games',
    author='DragonMinded',
    license='Public Domain',
    packages=[
        # Core packages
        'bemani',
        'bemani.common',
        'bemani.data',
        'bemani.data.api',
        'bemani.data.mysql',
        'bemani.protocol',

        # Wrapper scripts and WSGI imports
        'bemani.utils',

        # Frontend packages
        'bemani.frontend',
        'bemani.frontend.account',
        'bemani.frontend.admin',
        'bemani.frontend.arcade',
        'bemani.frontend.home',
        'bemani.frontend.static',
        'bemani.frontend.templates',

        # Game frontends
        'bemani.frontend.iidx',
        'bemani.frontend.popn',
        'bemani.frontend.jubeat',
        'bemani.frontend.bishi',
        'bemani.frontend.ddr',
        'bemani.frontend.sdvx',
        'bemani.frontend.reflec',
        'bemani.frontend.museca',

        # Backend packages
        'bemani.backend',
        'bemani.backend.core',
        'bemani.backend.ess',
        'bemani.backend.iidx',
        'bemani.backend.jubeat',
        'bemani.backend.popn',
        'bemani.backend.bishi',
        'bemani.backend.ddr',
        'bemani.backend.sdvx',
        'bemani.backend.reflec',
        'bemani.backend.museca',

        # API packages
        'bemani.api',
        'bemani.api.objects',

        # Testing game client packages
        'bemani.client',
        'bemani.client.iidx',
        'bemani.client.jubeat',
        'bemani.client.popn',
        'bemani.client.bishi',
        'bemani.client.ddr',
        'bemani.client.sdvx',
        'bemani.client.reflec',
        'bemani.client.museca',
    ],
    install_requires=[
        req for req in open('requirements.txt').read().split('\n') if len(req) > 0
    ],
    # None of these are required for operating any of the utilities found in this repo.
    # They are all present for speed. If you cannot compile arbitrary code or cython,
    # remove the ext_modules line and run setuptools again. Everything should work, but
    # it will run slower.
    ext_modules=extensions(),
    include_package_data=True,
    zip_safe=False,
)
