# -*- coding: utf-8 -*-
import os
import platform
import re
import typing
from logging.handlers import SysLogHandler

import CloudFlare
import pydomainextractor
import requests
import toml
import validators
from loguru import logger
from requests.auth import HTTPBasicAuth

dbg = True

if platform.system() == "Windows":
    logger.add("log_tcfig.log")
elif not dbg:
    syslog = SysLogHandler()
    logger.add(syslog)
else:
    logger.add("dbg.log", backtrace=True, diagnose=True)


class TFK:
    def __init__(self, config: typing.MutableMapping):
        self.config = config if self.check_credentials() else None
        self.router_list = self.tfk_get_routers

    @logger.catch
    def check_credentials(self) -> bool:
        """
        Check for credentials validity

        :param config: Credentials extracted from the config file
        :rtype: None
        """
        try:
            if self.config['API']['auth']:
                if self.config["API"]["user"] == "" or self.config["API"]["user"] is None:
                    logger.error("API endpoint username empty")
                    raise ValueError
                if self.config["API"]["pass"] == "" or self.config["API"]["pass"] is None:
                    logger.error("API endpoint password empty")
                    raise ValueError
        except KeyError:
            logger.exception(
                "Missing credentials or missing authentication declaration")
            raise
        return True

    @logger.catch
    def tfk_get_routers(self) -> typing.Tuple[typing.List[dict], typing.List[str]]:
        """
        Query Traefik API for the list of the HTTP Routers

        :param config: Credentials given by `get_credentials`
        :return: List of the HTTP Routers
        :rtype: list
        """
        api_route: str = "/api/http/routers"  # API Route to dump router config
        url: str = self.config["API"]["url"].rstrip(
            "/") + api_route  # Create URL
        # If the endpoint is not under authentication
        if not self.config["API"]["auth"]:
            with requests.get(url) as api_query:
                api_query.raise_for_status()
                # Get the list of HTTP Routers
                tfk_routers: typing.List[dict] = api_query.json()
                tfk_domains: typing.List[str] = self.tfk_parse_routers(
                    tfk_routers)
                return tfk_routers, tfk_domains
        else:
            # Only HTTPBasicAuth is currently supported
            with requests.get(url, auth=HTTPBasicAuth(username=self.config["API"]["user"],
                                                      password=self.config["API"]["pass"])) as api_query:
                api_query.raise_for_status()
                # Get the list of HTTP Routers
                tfk_routers: typing.List[dict] = api_query.json()
                tfk_domains: typing.List[str] = tfk_parse_routers(tfk_routers)
                return tfk_routers, tfk_domains

    def tfk_parse_routers(self, tfk_routers: typing.List[dict]) -> typing.List[str]:
        """
        Parse the Traefik HTTP routers list

        :param tfk_routers: Raw list of HTTP routers
        :type tfk_routers: list
        .. todo:: Take the state of the rule in mind
        """
        # Basic Host(`example.com`) rule
        basic_host_rules: list = []
        # Logical ((Host(`example.com`) && Path(`/traefik`))) rules to unpack
        logical_host_rules: list = []
        for router in tfk_routers:
            # Checks if it's a Host rule
            if 'Host' in router['rule']:
                # If logical operator
                if '&&' in router['rule'] or '||' in router['rule'] or "!" in router['rule']:
                    # Append to logical list
                    logical_host_rules.append(router['rule'])
                else:
                    # Append to the basic list
                    basic_host_rules.append(router['rule'])
        if len(basic_host_rules) < 1:
            logger.error("No basic rules found for Traefik, exiting")
            exit(120)
        tfk_domains = self.tfk_parse_basic_rules(host_rules=basic_host_rules)
        if len(logical_host_rules) > 0:
            logger.warning(
                "Logical rules aren't implemented and will be ignored")
        return tfk_domains

    @staticmethod
    def tfk_parse_basic_rules(host_rules: typing.List[str]) -> typing.List[str]:
        """
        Extract, and syntaxically the domain from the basic rule list

        :param host_rules: List of host rules
        :type host_rules: list
        :return: List of domains extracted
        :rtype: list
        """
        basic_domains: typing.List[str] = []
        # Only those characters are allowed in domains
        regex = re.compile(r"[a-z\d\-.]*", re.IGNORECASE | re.VERBOSE)
        for rule in host_rules:
            # Extract the domain name from rule
            basic_domains.append(rule.split("`")[1])
        for domain in basic_domains:
            # Checks that the domain is syntaxily correct
            if not regex.fullmatch(domain) or (not domain.startswith("-") or not domain.endswith("-")):
                # If not, remove the domain from the list
                basic_domains.remove(domain)
        return basic_domains
