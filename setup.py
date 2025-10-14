import os
import shutil
from setuptools import Command, setup


def extensions():
    # None of these are required for operating any of the utilities found in this repo.
    # They are all present for speed. If you cannot compile arbitrary code or cython,
    # run setup.py with "PURE_PYTHON=1" environment variable defined to skip compiling
    # extensions. Note that the pure python code will run slower.
    if 'PURE_PYTHON' in os.environ:
        # We've been asked not to compile extensions.
        with open("MANIFEST.in", "w") as wfp:
            with open("MANIFEST.assets", "r") as rfp:
                wfp.write(rfp.read())
        return []

    from setuptools import Extension
    from Cython.Build import cythonize

    cython_only_code = [
        # Alternative, orders of magnitude faster, memory-unsafe version of
        # LZ77 which drastically speeds up packet processing time.
        Extension(
            "bemani.protocol.lz77cpp",
            [
                "bemani/protocol/lz77cpp.cxx",
            ],
            language="c++",
            extra_compile_args=["-std=c++14"],
            extra_link_args=["-std=c++14"],
        ),
        # This is a memory-unsafe, orders of magnitude faster threaded implementation
        # of the pure python blend code which takes rendering rough animations down
        # from over an hour to around a minute.
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
    ]

    with open("MANIFEST.in", "w") as wfp:
        with open("MANIFEST.assets", "r") as rfp:
            wfp.write(rfp.read())
        with open("MANIFEST.cython", "r") as rfp:
            wfp.write(rfp.read())

    if 'EXPERIMENTAL_MYPYC_COMPILER' in os.environ:
        from mypyc.build import mypycify

        return [
            *mypycify(
                [
                    # List of modules that works as compiled mypyc code.
                    "bemani/protocol",
                    "bemani/common",
                ],
            ),
            *cythonize(
                [
                    # Always include code that must be compiled with cython.
                    *cython_only_code,
                    # The format module is not ready for mypyc compilation yet, there are some bugs in
                    # the compiler that prevent us from using it.
                    Extension(
                        "bemani.format.dxt",
                        [
                            "bemani/format/dxt.py",
                        ]
                    ),
                    # The types module is not ready for mypyc compilation yet, there are some bugs in
                    # the compiler that prevent us from using it.
                    Extension(
                        "bemani.format.afp.types.generic",
                        [
                            "bemani/format/afp/types/generic.py",
                        ]
                    ),
                ],
                language_level=3,
            ),
        ]
    else:
        return [
            *cythonize(
                [
                    # Always include code that must be compiled with cython.
                    *cython_only_code,
                    # Hot code for anything constructing or parsing a remote game packet.
                    Extension(
                        "bemani.protocol.binary",
                        [
                            "bemani/protocol/binary.py",
                        ]
                    ),
                    # Even though we have a C++ implementation of this, some of the code
                    # is still used as a wrapper to the C++ implementation and it is very
                    # hot code (almost every packet touches this).
                    Extension(
                        "bemani.protocol.lz77",
                        [
                            "bemani/protocol/lz77.py",
                        ]
                    ),
                    # Every single backend service uses this class for construction and
                    # parsing, so compiling this makes sense.
                    Extension(
                        "bemani.protocol.node",
                        [
                            "bemani/protocol/node.py",
                        ]
                    ),
                    # This is the top-level protocol marshall which gets touched at least
                    # once per packet, so its worth it to squeeze more speed out of this.
                    Extension(
                        "bemani.protocol.protocol",
                        [
                            "bemani/protocol/protocol.py",
                        ]
                    ),
                    # This is used to implement a convenient way of parsing/creating binary
                    # data and it is memory-safe accessses of bytes so it is necessarily
                    # a bottleneck.
                    Extension(
                        "bemani.protocol.stream",
                        [
                            "bemani/protocol/stream.py",
                        ]
                    ),
                    # This gets used less frequently (only on the oldest games) but it is
                    # still worth it to get a bit of a speed boost by compiling.
                    Extension(
                        "bemani.protocol.xml",
                        [
                            "bemani/protocol/xml.py",
                        ]
                    ),
                    # These types include operations such as matrix math and color conversion so
                    # it is worth it to speed this up when rendering animations.
                    Extension(
                        "bemani.format.afp.types.generic",
                        [
                            "bemani/format/afp/types/generic.py",
                        ]
                    ),
                    # DXT is slow enough that it might be worth it to write a C++ implementation of
                    # this at some point, but for now we squeeze a bit of speed out of this by compiling.
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


class CleanExtCommand(Command):
    description = 'Clean all compiled python extensions from the current directory.'

    user_options = []

    def initialize_options(self) -> None:
        pass

    def finalize_options(self) -> None:
        pass

    def run(self) -> None:
        print("Removing build directory...")
        shutil.rmtree(os.path.abspath("build/"), ignore_errors=True)
        for dirname, subdirList, fileList in os.walk(os.path.abspath(".")):
            for filename in fileList:
                if filename[-3:] == ".so":
                    fullname = os.path.join(dirname, filename)
                    print(f"Removing {fullname}")
                    os.remove(fullname)


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

        # Wrapper scripts, utilities and associated code.
        'bemani.utils',
        'bemani.sniff',
        'bemani.format',
        'bemani.format.afp',
        'bemani.format.afp.blend',
        'bemani.format.afp.types',

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
        'bemani.frontend.mga',
        'bemani.frontend.ddr',
        'bemani.frontend.sdvx',
        'bemani.frontend.reflec',
        'bemani.frontend.museca',
        'bemani.frontend.danevo',

        # Backend packages
        'bemani.backend',
        'bemani.backend.core',
        'bemani.backend.ess',
        'bemani.backend.iidx',
        'bemani.backend.jubeat',
        'bemani.backend.popn',
        'bemani.backend.bishi',
        'bemani.backend.mga',
        'bemani.backend.ddr',
        'bemani.backend.sdvx',
        'bemani.backend.reflec',
        'bemani.backend.museca',
        'bemani.backend.danevo',

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
        'bemani.client.danevo',
    ],
    install_requires=[
        req for req in open('requirements.txt').read().split('\n') if len(req) > 0
    ],
    ext_modules=extensions(),
    cmdclass={
        'clean_ext': CleanExtCommand,
    },
    include_package_data=True,
    zip_safe=False,
)
