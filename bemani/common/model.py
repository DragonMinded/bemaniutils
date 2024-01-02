from typing import Optional


class Model:
    """
    Object representing a parsed Model String.
    """

    def __init__(self, gamecode: str, dest: str, spec: str, rev: str, version: Optional[int]) -> None:
        """
        Initialize a Model object.

        Parameters:
            gamecode - Game code (such as LDJ)
            dest - Destination region for the game (such as J)
            spec - Spec for the game (such as A)
            rev - Revision of the game (such as A)
            version - Integer representing version, usually in the form of YYYYMMDDXX where
                      YYYY is a year, MM is a month, DD is a day and XX is sub-day versioning.
        """
        self.gamecode = gamecode
        self.dest = dest
        self.spec = spec
        self.rev = rev
        self.version = version

    @staticmethod
    def from_modelstring(model: str) -> "Model":
        """
        Parse a modelstring and return a Model

        Parameters:
            model - Modelstring in a form similar to "K39:J:B:A:2010122200". Note that
                    The last part (version number) may be left off.

        Returns:
            A Model object.
        """
        parts = model.split(":")
        if len(parts) == 5:
            gamecode, dest, spec, rev, version = parts
            return Model(gamecode, dest, spec, rev, int(version))
        elif len(parts) == 4:
            gamecode, dest, spec, rev = parts
            return Model(gamecode, dest, spec, rev, None)
        raise Exception(f"Couldn't parse model {model}")

    def __str__(self) -> str:
        if self.version is None:
            return f"{self.gamecode}:{self.dest}:{self.spec}:{self.rev}"
        else:
            return f"{self.gamecode}:{self.dest}:{self.spec}:{self.rev}:{self.version}"
