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
import platform
import re
import typing
from logging.handlers import SysLogHandler

import CloudFlare
import pydomainextractor
import requests
import toml
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

domain_extractor = pydomainextractor.DomainExtractor()

config_file_name = "config.toml"

# TODO: Implement cli args
auth = True


def get_credentials() -> typing.MutableMapping:
    """
    Get the credentials from the config file

    :return: Dict worth of credentials
    :rtype: Union[dict, MutableMapping]
    """
    if os.path.isfile("config.toml"):  # Checks for config file existence
        # Load credentials dict
        credentials = toml.load(open(config_file_name, "rt"))
        check_credentials(credentials)
        # FIXME: We shouldn't need this
        global auth
        auth = credentials['API']['auth']
        return credentials
    else:
        logger.exception("Config File not found")
        raise FileNotFoundError


def check_credentials(credentials: typing.MutableMapping) -> None:
    """
    Check for credentials validity

    :param credentials: Credentials extracted from the config file
    :rtype: None
    """
    try:
        if credentials['API']['auth']:
            if credentials["API"]["user"] == "" or credentials["API"]["user"] is None:
                logger.error("API endpoint username empty")
            if credentials["API"]["pass"] == "" or credentials["API"]["pass"] is None:
                logger.error("API endpoint password empty")
    except KeyError:
        logger.exception(
            "Missing credentials or missing authentication declaration")


# CF

@logger.catch
def cf_get_zones(credentials: typing.MutableMapping) -> typing.List[dict]:
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
        logger.exception("Cloudflare API Error, your token is likely invalid")
        raise e
    # Returns the zone list
    if len(cf_zone_list) < 1:
        logger.error("No zones on CF found")
        exit(121)
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
        if zone['status'] != "active":
            logger.warning(f" DNS zone for domain {zone['name']} isn't active")
            continue
        if "#dns_records:edit" not in zone['permissions']:
            logger.warning(
                f"DNS Record editing permissions lacking for zone {zone['name']}")
            continue
        cf_domains.append({'id': zone["id"], 'name': zone["name"]})
    if len(cf_domains) < 1:
        logger.error("No active domains found")
    return cf_domains


def cf_check_tld_existence(cf_domains: typing.List[dict], tfk_subdomains: typing.List[dict]) -> typing.Tuple[list[dict], list[dict]]:
    """
    Check if the TLDs in routers are actually on the CF's user zone

    :param cf_domains: List of all domains in the CF's user zone along with the zone ID
    :type cf_domains: list[dict]
    :param tfk_subdomains: List of computed (split between TLD, SLD, 3LD...)
    :return: Checked TLD list against CF and TFK
    :rtype: list[dict]
    """
    cf_domains_verified = []
    tfk_subdomains_verified = []
    for entry in tfk_subdomains:
        # Recreate the TLD
        domain = f"{entry['domain']}.{entry['suffix']}"
        for cf_pair in cf_domains:
            # If domain in cf_domains
            if domain == cf_pair["name"]:
                # Append to verified list
                if cf_pair not in cf_domains_verified:
                    cf_domains_verified.append(cf_pair)
                if entry not in tfk_subdomains_verified:
                    tfk_subdomains_verified.append(entry)
                break
    return cf_domains_verified, tfk_subdomains_verified


def cf_check_existence(cf_domains: typing.List[dict],
                       tfk_subdomains: typing.List[dict],
                       credentials: typing.Union[dict, typing.MutableMapping]):
    """
    Check if any subdomains are already in the zone

    :param cf_domains: List of domains in the CF's user zone along with the zone ID
    :type cf_domains: list[dict]
    :param tfk_subdomains:
    :param credentials: Credentials file
    :return: Computed domains not in CF
    """
    # Instantiate a CF class
    cf = CloudFlare.CloudFlare(token=credentials["CF"]["api_token"])
    # Query a dump of the DNS zones
    dns_records = [cf.zones.dns_records.get(
        zones["id"]) for zones in cf_domains]
    # Iterate over all the domains
    for entry in tfk_subdomains[:]:
        # Iterate over the dns_records list
        # Recreate the TLD
        domain = f"{entry['subdomain']}.{entry['domain']}.{entry['suffix']}"
        for zone in dns_records:
            for record in zone:
                # If already exists
                if domain == record["name"]:
                    # Remove from the list of domains
                    try:
                        tfk_subdomains.remove(entry)
                    except ValueError:
                        pass
    return tfk_subdomains


# TRAEFIK :

@logger.catch
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
            tfk_routers: typing.List[dict] = api_query.json()
            return tfk_routers
    else:
        # Only HTTPBasicAuth is currently supported
        with requests.get(url, auth=HTTPBasicAuth(username=credentials["API"]["user"],
                                                  password=credentials["API"]["pass"])) as api_query:
            api_query.raise_for_status()
            # Get the list of HTTP Routers
            tfk_routers: typing.List[dict] = api_query.json()
            return tfk_routers


def tfk_parse_routers(tfk_routers: typing.List[dict]):
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
        # Checks if it's an Host rule
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
    tfk_domains = tfk_parse_basic_rules(host_rules=basic_host_rules)
    if len(logical_host_rules) > 0:
        logger.warning("Logical rules aren't implemented and will be ignored")
    return tfk_domains


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


def main():
    credentials = get_credentials()
    # CF
    cf_zone_list = cf_get_zones(credentials)
    cf_domains = cf_parse_zones(cf_zone_list)
    # TFK
    tfk_routers = tfk_get_routers(credentials)
    tfk_domains = tfk_parse_routers(tfk_routers)
    tfk_subdomains = utils_extract_subdomains(tfk_domains)
    # Checks
    cf_domains_verified, tfk_subdomains_verified = cf_check_tld_existence(
        cf_domains, tfk_subdomains)
    tfk_subdomains_verified = cf_check_existence(
        cf_domains_verified, tfk_subdomains_verified, credentials)
    if len(tfk_subdomains_verified) < 1:
        logger.info("Nothing to do, exitting")
        exit(0)


if __name__ == '__main__':
    main()
