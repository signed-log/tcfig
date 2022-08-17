# -*- coding: utf-8 -*-
import pytest
import toml

import tcfig


class TestConfig:
    def test_config_not_existing(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            _ = tcfig.parse_config("a.toml")

    def test_broken_config(self, tmp_path):
        broken = """
            [A]
            a =

            [C]
            b = a
        """
        with open(f"{tmp_path}/1.toml", "wt") as f1:
            f1.write(broken)
        with pytest.raises(toml.TomlDecodeError):
            _ = tcfig.parse_config(f"{tmp_path}/1.toml")

    def test_incomplete_config(self, tmp_path):
        incomplete = """
            [TRAEFIK]
            url = "https://api.example.com" # Traefik API endpoint URL
            auth = true # Is the endpoint under authentication
            user = "" # If not under auth, keep both user and pass empty
            pass = ""

            [CLOUDFLARE]
            api_token = "" # API token with ZONE:READ and DNS:WRITE permissions
            proxied = true

            [IP]
            IPv4 = "" # Target IPv4
            # IPv6 = false # Uncomment this and comment (#) the other one to disable AAA records creation
            IPv6 = "" # Target IPv6
        """
        with open(f"{tmp_path}/incomplete.toml", "wt") as f1:
            f1.write(incomplete)
        with pytest.raises(ValueError):
            _ = tcfig.parse_config(f"{tmp_path}/incomplete.toml")
