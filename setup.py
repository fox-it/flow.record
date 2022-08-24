from setuptools import setup, find_packages

setup(
    name="flow.record",
    packages=["flow." + v for v in find_packages("flow")],
    install_requires=[
        "msgpack>=0.5.2",
    ],
    extras_require={
        # Note: these compression libraries do not work well with pypy
        "compression": [
            "lz4",
            "zstandard",
        ],
        "elastic": [
            "elasticsearch",
        ],
    },
    namespace_packages=["flow"],
    entry_points={
        "console_scripts": [
            "r=flow.record.tools.r:main",
            "rdd=flow.record.tools.rdd:main",
            "rselect=flow.record.tools.rselect:main",
            "rdump=flow.record.tools.rdump:main",
            "rgeoip=flow.record.tools.geoip:main",
        ],
    },
)
