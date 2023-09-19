#! /usr/bin/env python3
if __name__ == "__main__":
    import os
    path = os.path.abspath(os.path.dirname(__file__))
    name = os.path.basename(__file__)

    import sys
    sys.path.append(path)
    os.environ["SQLALCHEMY_SILENCE_UBER_WARNING"] = "1"

    import runpy
    runpy.run_module(f"bemani.utils.{name}", run_name="__main__")
