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
from logging.handlers import SysLogHandler
from typing import MutableMapping

import click
import CloudFlare
import pydomainextractor
import requests
import toml
import validators
from loguru import logger
from requests.auth import HTTPBasicAuth

g_dev_debug = True  # Dev debug switch with Backtrace and diagnosis on

if platform.system() == "Windows":
    logger.add("log_tcfig.log")
elif not g_dev_debug:
    syslog = SysLogHandler()
    logger.add(syslog)
    if platform.system() == "Darwin":
        # TODO: Add to docs
        logger.warning(
            "ASL (default SysLogHandler on MacOS), doesn't record INFO and DEBUG log priorities by default")
elif g_dev_debug:
    logger.add("g_dbg.log", backtrace=True, diagnose=True)

g_domain_extractor = pydomainextractor.DomainExtractor()

g_config_file_name = "config.toml"

g_auth = True


@logger.catch
def parse_config(filename=g_config_file_name) -> MutableMapping:
    """
    Get the credentials from the config file

    :return: Dict worth of credentials
    :rtype: Union[dict, MutableMapping]
    """
    if os.path.isfile(filename):  # Checks for config file existence
        # Load credentials dict
        config = toml.load(open(filename, "rt"))
        if check_credentials(config):
            return config
        else:
            logger.exception("Credentials are invalid")
    else:
        logger.exception("Config File not found")
        raise FileNotFoundError


def check_credentials(config: MutableMapping) -> bool:
    """
    Check for credentials validity

    :param config: Credentials extracted from the config file
    :rtype: None
    """
    try:
        if config['API']['auth']:
            if config["API"]["user"] == "" or config["API"]["user"] is None:
                logger.error("API endpoint username empty")
                return False
            if config["API"]["pass"] == "" or config["API"]["pass"] is None:
                logger.error("API endpoint password empty")
                return False
    except KeyError:
        logger.exception(
            "Missing credentials or missing authentication declaration")
        raise
    else:
        return True


# CF

@logger.catch
def cf_get_zones(config: MutableMapping) -> list[dict]:
    """
    Query Cloudflare API and export the zones of the account

    :param config: Credentials given by `get_credentials`
    :return: List of the zones
    :rtype: list
    """
    try:
        # Instantiate a CF class
        cf_instance = CloudFlare.CloudFlare(token=config["CF"]["api_token"])
        # Get the zone list
        cf_zone_list: list[dict] = cf_instance.zones.get()
    except CloudFlare.exceptions.CloudFlareAPIError:
        logger.exception("Cloudflare API Error, your token is likely invalid")
        raise
    # Returns the zone list
    if len(cf_zone_list) < 1:
        logger.error("No zones on CF found")
        exit(121)
    cf_domains: list[dict] = cf_parse_zones(cf_zone_list)
    return cf_domains


def cf_parse_zones(cf_zone_list: list[dict]) -> list[dict]:
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
        exit(122)
    return cf_domains


def cf_check_tld_existence(cf_domains: list[dict], tfk_subdomains: list[dict]) \
        -> tuple[list[dict], list[dict]]:
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


def cf_check_existence(cf_domains: list[dict],
                       tfk_subdomains: list[dict],
                       config: MutableMapping) -> list[dict]:
    """
    Check if any subdomains are already in the zone

    :param cf_domains: List of domains in the CF's user zone along with the zone ID
    :type cf_domains: list[dict]
    :param tfk_subdomains:
    :param config: Credentials file
    :return: Computed domains not in CF
    """
    # Instantiate a CF class
    try:
        cf_instance = CloudFlare.CloudFlare(token=config["CF"]["api_token"])
    except CloudFlare.exceptions.CloudFlareAPIError:
        logger.exception("Cloudflare API Error")
        raise
    # Query a dump of the DNS zones
    dns_records = [cf_instance.zones.dns_records.get(
        zones["id"]) for zones in cf_domains]
    # Iterate over all the domains
    for entry in tfk_subdomains[:]:
        # Iterate over the dns_records list
        # Recreate the TLD
        domain = f"{entry['subdomain']}.{entry['domain']}.{entry['suffix']}" if entry["subdomain"].isalnum() \
            else f"{entry['domain']}.{entry['suffix']}"  # Support bare TLD
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
def tfk_get_routers(config: MutableMapping) -> list[str]:
    """
    Query Traefik API for the list of the HTTP Routers

    :param config: Credentials given by `get_credentials`
    :return: List of the HTTP Routers
    :rtype: list
    """
    api_route: str = "/api/http/routers"  # API Route to dump router config
    url: str = config["API"]["url"].rstrip("/") + api_route  # Create URL
    # If the endpoint is not under authentication
    if not config["API"]["auth"]:
        with requests.get(url) as api_query:
            api_query.raise_for_status()
            # Get the list of HTTP Routers
            tfk_routers: list[dict] = api_query.json()
            tfk_domains: list[str] = tfk_parse_routers(tfk_routers)
            return tfk_domains
    else:
        # Only HTTPBasicAuth is currently supported
        with requests.get(url, auth=HTTPBasicAuth(username=config["API"]["user"],
                                                  password=config["API"]["pass"])) as api_query:
            api_query.raise_for_status()
            # Get the list of HTTP Routers
            tfk_routers: list[dict] = api_query.json()
            tfk_domains: list[str] = tfk_parse_routers(tfk_routers)
            return tfk_domains


def tfk_parse_routers(tfk_routers: list[dict]) -> list[str]:
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
    tfk_domains = tfk_parse_basic_rules(host_rules=basic_host_rules)
    if len(logical_host_rules) > 0:
        logger.warning("Logical rules aren't implemented and will be ignored")
    return tfk_domains


def tfk_parse_basic_rules(host_rules: list[str]) -> list[str]:
    """
    Extract, and syntaxically the domain from the basic rule list

    :param host_rules: List of host rules
    :type host_rules: list
    :return: List of domains extracted
    :rtype: list
    """
    basic_domains: list[str] = []
    # Only those characters are allowed in domains
    regex = re.compile(r"[a-z\d][a-z\d\-.]*[a-z\d]",
                       re.IGNORECASE | re.VERBOSE)
    for rule in host_rules:
        # Extract the domain name from rule
        basic_domains.append(rule.split("`")[1])
    for domain in basic_domains:
        # Checks that the domain is syntaxily correct
        if not regex.fullmatch(domain):
            # If not, remove the domain from the list
            basic_domains.remove(domain)
    return basic_domains


def split_subdomains(domains: list[str]) -> list[dict]:
    """
    Extract the domain and subdomain from the domain

    :param domains: List of extracted domains from Traefik
    :return: List of parsed subdomains
    :rtype: list[dict]
    """
    subdomain_list: list[dict] = []
    for domain in domains:
        # Extract domain and sub from domain
        subdomain_list.append(g_domain_extractor.extract(domain))
    return subdomain_list


def gen_records(tfk_subdomains: list[dict],
                cf_domains: list[dict],
                config: MutableMapping) -> dict:
    """
    Generate the missing records for cf_add_record

    :param tfk_subdomains: List of all the subdomains to add
    :param cf_domains: List of all zones of the account
    :param config: List of the credentials
    :return:
    """
    # Fetch IP Adresses
    ipv4, ipv6 = ip(config)
    # Records and zone info about the domains
    zones_to_update: dict[dict] = {}
    # TODO: Generate that dict on the fly along other functions
    for zone in cf_domains:
        for entry in tfk_subdomains:
            # If the zone correspond to the domain
            if zone["name"] == f"{entry['domain']}.{entry['suffix']}":
                if zone["name"] not in zones_to_update.keys():  # Checks for the header
                    # Add the zone ID as a header to the dict list
                    zones_to_update[zone["name"]] = {
                        'id': zone['id'], 'domains': [], 'records': []}
                zones_to_update[zone["name"]]["domains"].append(
                    f"{entry['subdomain']}.{entry['domain']}.{entry['suffix']}" if entry["subdomain"].isalnum()
                    else f"{entry['domain']}.{entry['suffix']}"
                )
    for zone in zones_to_update.keys():
        for domain in zones_to_update[zone]['domains']:
            if not ipv6:  # Only append A records if ipv6 is disabled
                zones_to_update[zone]['records'].append(
                    {
                        "name": domain,
                        "type": "A",
                        "content": ipv4,
                        'ttl': int(config["CF"]["TTL"]),
                        'proxied': bool(config["CF"]["proxied"])
                    }
                )
            else:  # Append both A and AAA records
                zones_to_update[zone]['records'].append(
                    {
                        "name": domain,
                        "type": "A",
                        "content": ipv4,
                        'ttl': int(config["CF"]["TTL"]),
                        'proxied': bool(config["CF"]["proxied"])
                    }
                )
                zones_to_update[zone]['records'].append(
                    {
                        "name": domain,
                        "type": "AAAA",
                        "content": ipv6,
                        'ttl': int(config["CF"]["TTL"]),
                        'proxied': bool(config["CF"]["proxied"])
                    }
                )
    return zones_to_update


@logger.catch
def cf_add_record(zones_to_update: dict[dict],
                  config: MutableMapping):
    """
    Add records to CF
    :param zones_to_update: List of dns records to add
    :param config: List of credentials and options
    :return:
    """
    try:
        cf_instance = CloudFlare.CloudFlare(token=config["CF"]["api_token"])
    except CloudFlare.exceptions.CloudFlareAPIError as e:
        logger.exception(f"Cloudflare API Error: {e}")
        raise
    for zone in zones_to_update.keys():
        zone_id = zones_to_update[zone]["id"]  # Zone ID for the given zone
        # All the records for the given zone
        record_data = zones_to_update[zone]["records"]
        for data in record_data:
            try:
                cf_instance.zones.dns_records.post(
                    zone_id, data=data)  # Post the record
            except CloudFlare.exceptions.CloudFlareAPIError as e:
                logger.exception(
                    f"Record {data['name']} with record type {data['type']}: {e}")


def ip(config: MutableMapping) -> tuple[str, str | bool]:
    """
    Grabs Public IP

    :param config: List of credentials
    .. todo:: Automatic IP fetching (will need to wait for CLI)
    :return:
    """
    ipv4: str = ""
    ipv6: str | bool = ""
    try:
        if validators.ipv4(config["Records"]["IPv4"]):
            ipv4 = config["Records"]["IPv4"]
        else:
            logger.error("Missing or invalid IPv4, aborting")
            exit(139)
    except KeyError:
        logger.error("Missing configuration key for IPv4 aborting")
        raise
    try:
        if isinstance(config["Records"]["IPv6"], str) and validators.ipv6(config["Records"]["IPv6"]):
            ipv6 = config["Records"]["IPv6"]
        elif not config["Records"]["IPv6"]:
            ipv6 = False
        else:
            logger.error("Missing or invalid IPv6, aborting")
            exit(140)
    except KeyError:
        logger.error("Missing configuration key for IPv6, aborting")
        raise
    return ipv4, ipv6

# Validate


def validate_config_file(ctx, param, value):
    if value != g_config_file_name:
        try:
            _ = toml.loads(value)
        except toml.decoder.TomlDecodeError as e:
            logger.exception(f"Decoding error on config file : {e}")
            raise click.BadParameter(f"Decoding error on config file : {e}")
        else:
            return value
    else:
        return value

# CLI


@click.group()
@click.option('--debug/--no-debug', default=False, help="Enable debug mode")
@click.option("-c",
              "--config-file",
              type=click.Path(exists=True),
              callback=validate_config_file,
              default=g_config_file_name,
              required=False,
              show_default=True,
              help="Config file path")
@click.pass_context
def cli(ctx, debug, config_file):
    ctx.ensure_object(dict)
    ctx.obj["DEBUG"] = debug
    ctx.obj["CONFIG"] = config_file


@logger.catch
@cli.command()
@click.option("-p/-P",
              "--post/--no-post",
              default=True,
              show_default=True,
              help="Post the records to Cloudflare's API")
@click.option("-e/-E",
              "--check-exists/--no-exists-check",
              default=True,
              show_default=True,
              help="Disable the checks against CF zones and force add records"
              )
@click.pass_context
def run(ctx, post, check_exists):
    ctx.obj["POST"] = post
    ctx.obj["CHECK"] = check_exists
    main(ctx)


def main(ctx):
    config = parse_config(ctx.obj["CONFIG"])  # Parse config file
    # CF
    # Get zones from the account and the parsed DNS ones
    cf_domains = cf_get_zones(config)
    # TFK
    tfk_domains = tfk_get_routers(
        config)  # Get routers from the Traefik install
    tfk_subdomains = split_subdomains(tfk_domains)
    # Checks
    cf_domains_verified, tfk_subdomains_verified = cf_check_tld_existence(
        cf_domains, tfk_subdomains)  # Checks what TLDs exist on the account
    if ctx.obj["CHECK"]:
        logger.info("Checking for record existence")
        tfk_subdomains_verified = cf_check_existence(
            cf_domains_verified, tfk_subdomains_verified, config)  # Check what subdomains are to be added
    if len(tfk_subdomains_verified) < 1:  # If nothing to do
        logger.info("Nothing to do, exiting")
        exit(0)
    records = gen_records(
        tfk_subdomains_verified, cf_domains_verified, config)  # Generate records
    if ctx.obj["POST"]:
        logger.info("Posting to Cloudflare")
        cf_add_record(records, config)  # Add records to Cloudflare
    else:
        logger.info("CloudFlare post routine bypassed")
        exit(0)


if __name__ == '__main__':
    cli(obj={})
