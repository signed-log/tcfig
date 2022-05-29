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
import re
import typing

import click
import CloudFlare
import pydomainextractor
import requests
import requests as curl
import toml
import validators
from requests.auth import HTTPBasicAuth

domain_extractor = pydomainextractor.DomainExtractor()

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


def cf_parse_zones(cf_zone_list: typing.List[dict]) -> typing.List[str]:
    """
    Extract domains from the CF zone list

    :param cf_zone_list: List of the zones
    :type cf_zone_list: list
    :return: List of valid (active and with enough permssions) CF domains
    :rtype: list[str]
    """
    cf_domains = []  # List of the domains of the account
    for zone in cf_zone_list:
        if zone['status'] != "active" or "#dns_records:edit" not in zone[
                'permissions']:  # Check permission and status
            continue
        cf_domains.append(zone['name'])
    return cf_domains


def cf_check_sld(parsed_subdomains: typing.List[dict],
                 cf_domains: typing.List[str]) -> typing.List[dict]:
    """
    Check what domains are in the user's account

    :param parsed_subdomains: Extracted domain info
    :type parsed_subdomains: list[dict]
    :param cf_domains: List of valid domains
    :type cf_domains: list[str]
    .. seealso:: cf_parse_zones()
    :return: List of existing domains to parse
    :return: list[dict]
    """
    for index, domain in enumerate(parsed_subdomains):
        domain_to_check: str = domain["domain"] + domain["suffix"]
        if domain_to_check not in cf_domains:
            parsed_subdomains.pop(index)
    return parsed_subdomains


def cf_check_for_existence(domain_list: list[dict]):
    pass


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


def tfk_parse_routers(traefik_routers: typing.List[dict]):
    """
    Parse the Traefik HTTP routers list

    :param traefik_routers: Raw list of HTTP routers
    :type traefik_routers: list
    .. todo:: Take the state of the rule in mind
    """
    basic_host_rules: list = []  # Basic Host(`example.com`) rule
    # yapf: disable
    logical_host_rules: list = []  # Logical ((Host(`example.com`) && Path(`/traefik`))) rules to unpack
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
    if len(logical_host_rules) > 0:
        print("WARNING, LOGICAL RULES AREN'T IMPLEMENTED AND WILL BE IGNORED")
    return basic_domains


def tfk_parse_basic_rules(host_rules: typing.List[str]) -> typing.List[str]:
    """
    Extract, and syntaxically the domain from the basic rule list

    :param host_rules: List of host rules
    :type host_rules: list
    :return: List of domains extracted
    :rtype: list
    """
    basic_domains = []
    regex = re.compile(
        r"[a-z\d\-.]*", re.IGNORECASE
        | re.VERBOSE)  # Only those characters are allowed in domains
    for rule in host_rules:
        basic_domains.append(
            rule.split("`")[1])  # Extract the domain name from rule
    for domain in basic_domains:
        if not regex.fullmatch(domain) or (
                not domain.startswith("-") or not domain.endswith("-")
        ):  # Checks that the domain is syntaxily correct
            basic_domains.remove(
                domain)  # If not, remove the domain from the list
    return basic_domains


def utils_extract_subdomains(domains: typing.List[str]) -> typing.List[dict]:
    """
    Extract the domain and subdomain from the domain

    :param domains: List of extracted domains from Traefik
    :return: List of parsed subdomains
    :rtype: list[dict]
    """
    parsed_subdomains: typing.List[dict] = []
    for domain in domains:
        parsed_subdomains.append(domain_extractor.extract(
            domain))  # Extract domain and sub from domain
    return parsed_subdomains
