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
        "geoip": [
            "maxminddb",
        ],
    },
    namespace_packages=["flow"],
    entry_points={
        "console_scripts": [
            "rdump=flow.record.tools.rdump:main",
            "rgeoip=flow.record.tools.geoip:main",
        ],
    },
)
