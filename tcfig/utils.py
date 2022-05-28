# -*- coding: utf-8 -*-
import os
import pathlib


class TcfigError(Exception):
    pass


def secure_file(file: str or pathlib.Path) -> bool:
    os.chmod(0o600, file)
    return True
