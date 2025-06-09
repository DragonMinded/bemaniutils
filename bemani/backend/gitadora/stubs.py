# vim: set fileencoding=utf-8
from typing import Optional

from bemani.backend.gitadora.base import GitadoraBase
from bemani.common import VersionConstants


class Gitadora(GitadoraBase):
    name = "Gitadora"
    version = VersionConstants.GITADORA


class GitadoraOverDrive(GitadoraBase):
    name = "GITADORA OverDrive"
    version = VersionConstants.GITADORA_OVERDRIVE

    def previous_version(self) -> Optional[GitadoraBase]:
        return Gitadora(self.data, self.config, self.model)


class GitadoraTriBoost(GitadoraBase):
    name = "GITADORA Tri-Boost"
    version = VersionConstants.GITADORA_TRIBOOST

    def previous_version(self) -> Optional[GitadoraBase]:
        return GitadoraOverDrive(self.data, self.config, self.model)


class GitadoraTriBoostReEVOLVE(GitadoraBase):
    name = "GITADORA Tri-Boost Re:EVOLVE"
    version = VersionConstants.GITADORA_TRIBOOST_RE_EVOLVE

    def previous_version(self) -> Optional[GitadoraBase]:
        return GitadoraTriBoost(self.data, self.config, self.model)


class GitadoraMatixx(GitadoraBase):
    name = "GITADORA Matixx"
    version = VersionConstants.GITADORA_MATIXX

    def previous_version(self) -> Optional[GitadoraBase]:
        return GitadoraTriBoostReEVOLVE(self.data, self.config, self.model)


class GitadoraExchain(GitadoraBase):
    name = "GITADORA EXCHAIN"
    version = VersionConstants.GITADORA_EXCHAIN

    def previous_version(self) -> Optional[GitadoraBase]:
        return GitadoraMatixx(self.data, self.config, self.model)
