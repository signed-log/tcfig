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
import os
import re
import typing

import CloudFlare
import pydomainextractor
import requests
import toml
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
        # Load credentials dict
        credentials = toml.load(open(config_file_name, "rt"))
        global auth
        auth = credentials['API']['auth']
        return credentials
    else:
        raise FileNotFoundError("Check that config file is correctly named")


# CF


def cf_get_zones(credentials: typing.Union[dict, typing.MutableMapping]) -> typing.List[dict]:
    """
    Query Cloudflare API and export the zones of the account

    :param credentials: Credentials given by `get_credentials`
    :return: List of the zones
    :rtype: list
    """
    try:
        # Instantiate a CF class
        cf = CloudFlare.CloudFlare(token=credentials["CF"]["api_token"])
        # Get the zone list
        cf_zone_list: typing.List[dict] = cf.zones.get()
    except CloudFlare.CloudFlareAPIError as e:
        raise e
    # Returns the zone list
    return cf_zone_list


def cf_parse_zones(cf_zone_list: typing.List[dict]) -> typing.List[typing.Dict[str, str]]:
    """
    Extract domains from the CF zone list

    :param cf_zone_list: List of the zones
    :type cf_zone_list: list
    :return: List of valid (active and with enough permssions) CF domains
    :rtype: list[str]
    """
    cf_domains = []  # List of the domains of the account
    for index, zone in enumerate(cf_zone_list):
        # Check permission and status
        if zone['status'] != "active" or "#dns_records:edit" not in zone['permissions']:
            continue
        cf_domains.append({'id': zone["id"], 'name': zone["name"]})
    return cf_domains


def cf_check_sld(parsed_subdomains: typing.List[dict], cf_domains: typing.Dict[str, str]) -> typing.List[dict]:
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


def cf_check_existence(cf_domains: typing.List[dict], tfk_subdomains: typing.List[dict]):
    """
    Check if any subdomains are already in the zone

    :param cf_domains:
    :param tfk_subdomains:
    :return:
    """


def cf_check_tld_existence(cf_domains: typing.List[dict], tfk_subdomains: typing.List[dict]):
    for entry in tfk_subdomains:
        domain = entry['domain'] + '.' + entry['suffix']
        if domain not in cf_domains:
            cf_domains.remove(entry)


# TRAEFIK :


def tfk_get_routers(credentials: typing.Union[dict, typing.MutableMapping]) -> typing.List[dict]:
    """
    Query Traefik API for the list of the HTTP Routers

    :param credentials: Credentials given by `get_credentials`
    :return: List of the HTTP Routers
    :rtype: list
    """
    api_route: str = "/api/http/routers"  # API Route to dump router config
    url: str = credentials["API"]["url"].rstrip("/") + api_route  # Create URL
    # If the endpoint is not under authentication
    if not auth:
        with requests.get(url) as api_query:
            api_query.raise_for_status()
            # Get the list of HTTP Routers
            traefik_routers: typing.List[dict] = api_query.json()
            return traefik_routers
    else:
        # Only HTTPBasicAuth is currently supported
        with requests.get(url, auth=HTTPBasicAuth(username=credentials["API"]["user"],
                                                  password=credentials["API"]["pass"])) as api_query:
            api_query.raise_for_status()
            # Get the list of HTTP Routers
            traefik_routers: typing.List[dict] = api_query.json()
            return traefik_routers


def tfk_parse_routers(traefik_routers: typing.List[dict]):
    """
    Parse the Traefik HTTP routers list

    :param traefik_routers: Raw list of HTTP routers
    :type traefik_routers: list
    .. todo:: Take the state of the rule in mind
    """
    # Basic Host(`example.com`) rule
    basic_host_rules: list = []
    # Logical ((Host(`example.com`) && Path(`/traefik`))) rules to unpack
    logical_host_rules: list = []
    for router in traefik_routers:
        # Checks if it's an Host rule
        if 'Host' in router['rule']:
            # Appends to the basic list
            basic_host_rules.append(router['rule'])
            # If logical operator
            if '&&' in router['rule'] or '||' in router['rule'] or "!" in router['rule']:
                # Append to logical list
                logical_host_rules.append(router['rule'])
                # Remove from basic list
                basic_host_rules.remove(router['rule'])
    tfk_domains = tfk_parse_basic_rules(host_rules=basic_host_rules)
    if len(logical_host_rules) > 0:
        print("WARNING, LOGICAL RULES AREN'T IMPLEMENTED AND WILL BE IGNORED")
    return tfk_domains


def tfk_parse_basic_rules(host_rules: typing.List[str]) -> typing.List[str]:
    """
    Extract, and syntaxically the domain from the basic rule list

    :param host_rules: List of host rules
    :type host_rules: list
    :return: List of domains extracted
    :rtype: list
    """
    basic_domains = []
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


def utils_extract_subdomains(domains: typing.List[str]) -> typing.List[dict]:
    """
    Extract the domain and subdomain from the domain

    :param domains: List of extracted domains from Traefik
    :return: List of parsed subdomains
    :rtype: list[dict]
    """
    subdomain_list: typing.List[dict] = []
    for domain in domains:
        # Extract domain and sub from domain
        subdomain_list.append(domain_extractor.extract(domain))
    return subdomain_list
