"""Rechten van de geheimbestanden in ``/appdata/secrets`` (``hub-link.json``, ``vault.key``, ``identity.ed25519``).

Doel: alleen leesbaar voor de eigen gebruiker (0600). Een TrueNAS-dataset met de preset *Apps* heeft NFSv4-ACL's met
overgeërfde ACE's; ZFS negeert dan de 0600 van ``open()`` (``aclinherit=passthrough``: de rechten van een nieuw
bestand komen uit de overerfbare ACE's) en kan ``chmod`` weigeren (``aclmode=restricted``). Daarom:

- na het aanmaken altijd ``fchmod(0600)`` proberen (:func:`alleen_eigenaar`);
- bij het lezen blijven geen gewoon bestand (symlinks weigert de aanroeper met ``O_NOFOLLOW``), een andere eigenaar en
  wereld-schrijfbaar altijd onleesbaar; rechten voor groep of anderen zijn alleen goed als het bestand een NFSv4-ACL
  draagt (dan bepaalt de ACL van de dataset ze, niet deze dienst). Op een gewoon bestandssysteem blijft alleen 0600
  goed, zoals voorheen.
"""

from __future__ import annotations

import contextlib
import os
import stat

# TrueNAS (ZFS op Linux) toont de NFSv4-ACL als ``system.nfs4_acl_xdr``; de Linux-NFS-client als ``system.nfs4_acl``.
NFS4_ACL_XATTRS = ("system.nfs4_acl_xdr", "system.nfs4_acl")


def alleen_eigenaar(fd: int) -> None:
    """0600 na het aanmaken; een ACL-dataset mag weigeren (de leescontrole beslist dan, :func:`eigen_geheim`)."""
    with contextlib.suppress(OSError):
        os.fchmod(fd, 0o600)


def nfs4_acl(fd: int) -> bool:
    for naam in NFS4_ACL_XATTRS:
        try:
            os.getxattr(fd, naam)
            return True
        except OSError:
            continue
    return False


def eigen_geheim(fd: int) -> bool:
    """Of het geopende bestand een geheim van deze dienst mag zijn (zie de moduletekst)."""
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o002:
        return False
    if not st.st_mode & 0o077:
        return True
    if not nfs4_acl(fd):
        return False
    alleen_eigenaar(fd)  # aanscherpen waar de ACL het toestaat; lukt het niet, dan is het onvermijdelijk
    return True
