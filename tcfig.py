#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    Link Traefik to Cloudflare DNS
    Copyright (C) 2O22  Nicolas signed-log FORMICHELLA

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""
import argparse
import os
import pathlib
import typing

import CloudFlare
import requests
import requests as curl
import toml
import validators
from requests.auth import HTTPBasicAuth

config_file_name = "config.toml"

# TODO: Implement cli args
auth = True


def get_credentials() -> typing.Union[dict, typing.MutableMapping]:
    """
    Get the credentials from the config file

    :return: Dict worth of credentials
    :rtype: Union[dict, MutableMapping]
    """
    if os.path.isfile("config.toml"):  # Checks for config file existence
        credentials = toml.load(open(config_file_name,
                                     "rt"))  # Load credentials dict
        return credentials
    else:
        raise FileNotFoundError("Check that config file is correctly named")


def cf_get_zones(
    credentials: typing.Union[dict,
                              typing.MutableMapping]) -> typing.List[dict]:
    """
    Query Cloudflare API and export the zones of the account

    :param credentials: Credentials given by `get_credentials`
    :return: List of the zones
    :rtype: list
    """
    try:
        cf = CloudFlare.CloudFlare(
            token=credentials["CF"]["api_token"])  # Instantiate a CF class
        cf_zone_list: typing.List[dict] = cf.zones.get()  # Get the zone list
    except CloudFlare.CloudFlareAPIError:
        raise LookupError("The provided API token is likely not valid")
    return cf_zone_list  # Returns the zone list


def tfk_get_routers(
    credentials: typing.Union[dict,
                              typing.MutableMapping]) -> typing.List[dict]:
    """
    Query Traefik API for the list of the HTTP Routers

    :param credentials: Credentials given by `get_credentials`
    :return: List of the HTTP Routers
    :rtype: list
    """
    api_route: str = "/api/http/routers"  # API Route to dump router config
    url: str = credentials["API"]["url"].rstrip("/") + api_route  # Create URL
    if not auth:  # If the endpoint is not under authentication
        with requests.get(url) as api_query:
            api_query.raise_for_status()
            traefik_routers: typing.List[dict] = api_query.json(
            )  # Get the list of HTTP Routers
            return traefik_routers
    else:  # If the endpoint is under authentication
        with requests.get(
                url,
                auth=HTTPBasicAuth(username=credentials["API"]["user"],
                                   password=credentials["API"]["pass"])
        ) as api_query:  # Only HTTPBasicAuth is currently supported
            api_query.raise_for_status()
            traefik_routers: typing.List[dict] = api_query.json(
            )  # Get the list of HTTP Routers
            return traefik_routers


# FIXME: Parses disabled rules
def tfk_parse_routers(traefik_routers: typing.List[dict]):
    basic_host_rules: list = []  # Basic Host(`example.com`) rule
    # yapf: disable
    logical_host_rules: list = []  # Logical ((Host(`example.org`) && Path(`/traefik`))) rules to unpack
    # yapf: enable
    for router in traefik_routers:
        if 'Host' in router['rule']:  # Checks if it's an Host rule
            basic_host_rules.append(
                router['rule'])  # Appends to the basic list
            if '&&' in router['rule'] or '||' in router[
                    'rule'] or "!" in router['rule']:  # If logical operator
                logical_host_rules.append(
                    router['rule'])  # Append to logical list
                basic_host_rules.remove(
                    router['rule'])  # Remove from basic list
    basic_domains = tfk_parse_basic_rules(host_rules=basic_host_rules)
    logical_domains = tfk_parse_logical_rules(host_rules=logical_host_rules)


def tfk_parse_basic_rules(host_rules: typing.List[str]):
    basic_domains = []
    for rule in host_rules:
        basic_domains.append(rule.split("`")[1])
    return basic_domains


def tfk_parse_logical_rules(host_rules: typing.List[str]):
    logical_domains = []
    return logical_domains
