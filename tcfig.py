#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import platform
import re
from logging.handlers import SysLogHandler
from sys import exit
from typing import MutableMapping

import click
import CloudFlare
import pydomainextractor
import requests
import toml
import validators
from loguru import logger
from requests.auth import HTTPBasicAuth

legal = """
    Link Traefik to Cloudflare® DNS
    Copyright (C) 2O22 The tcfig authors

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

    Cloudflare, the Cloudflare logo, Cloudflare DNS are trademarks and/or registered trademarks of Cloudflare, Inc.
    in the United States and other jurisdictions.
    """

g_dev_debug = False  # Dev debug switch with Backtrace and diagnosis on

# Logging setup

if platform.system() == "Windows":
    logger.add("log_tcfig.log")
elif not g_dev_debug:
    if platform.system() == "Linux":
        # Default log handler is systemd-journald on most machines, which doesn't play well with SysLogHandler
        logger.add("log_tcfig.log")
    elif platform.system() == "Darwin":
        # TODO: Add to docs
        # TODO: Need MacOS tests
        syslog = SysLogHandler()
        logger.add(syslog)
        logger.warning(
            "ASL (default SysLogHandler on MacOS), doesn't record INFO and DEBUG log priorities by default")
if g_dev_debug:
    logger.add("g_dbg.log", backtrace=True, diagnose=True)

g_domain_extractor = pydomainextractor.DomainExtractor()

g_config_file_name = "config.toml"  # Default config file name

g_context_options = {'help_option_names': [
    '-h', '--help']}  # Help options for CLI


def parse_config(filename=g_config_file_name) -> MutableMapping:
    """
    Parse the TOML config file

    :param filename: Set a custom config file, defaults to ./config.toml
    :type filename: str, optional
    :return: Dict worth of credentials
    :rtype: MutableMapping
    """
    # Checks for config file existence
    if os.path.isfile(filename):
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
    :type config: MutableMapping
    :return: Validity of the credentials provided
    :rtype: bool
    """
    try:
        if config['TRAEFIK']['auth']:
            if config["TRAEFIK"]["user"] == "" or config["TRAEFIK"]["user"] is None:
                logger.error("API endpoint username empty")
                return False
            if config["TRAEFIK"]["pass"] == "" or config["TRAEFIK"]["pass"] is None:
                logger.error("API endpoint password empty")
                return False
    except KeyError:
        logger.exception(
            "Missing credentials or missing authentication declaration")
        raise
    else:
        return True


# CF


def cf_get_zones(config: MutableMapping) -> list[dict]:
    """
    Query Cloudflare® API and export the zones of the account

    :param config: Parsed config file
    :return: Parsed domain lists
    :rtype: list[dict]
    """
    try:
        # Instantiate a CF class
        cf_instance = CloudFlare.CloudFlare(
            token=config["CLOUDFLARE"]["api_token"])
        # Get the zone list
        cf_zone_list: list[dict] = cf_instance.zones.get()
    except CloudFlare.exceptions.CloudFlareAPIError:
        logger.exception("Cloudflare® API Error, your token is likely invalid")
        raise
    # Returns the zone list
    if len(cf_zone_list) < 1:
        logger.error("No zones on Cloudflare found")
        exit(121)
    cf_domains: list[dict] = cf_parse_zones(cf_zone_list)
    return cf_domains


def cf_parse_zones(cf_zone_list: list[dict]) -> list[dict]:
    """
    Extract domains from the CF zone list

    :param cf_zone_list: List of the zones
    :type cf_zone_list: list
    :return: List of valid (active and with enough permssions) CF domains
    :rtype: list[dict]
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
    :rtype: tuple(list[dict], list[dict])
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
    :param tfk_subdomains: List of Traefik subdomains
    :type tfk_subdomains: list[dict]
    :param config: Parsed config file
    :type config: MutableMapping
    :return: Computed domains not in CF
    """
    # Instantiate a CF class
    try:
        cf_instance = CloudFlare.CloudFlare(
            token=config["CLOUDFLARE"]["api_token"])
    except CloudFlare.exceptions.CloudFlareAPIError:
        logger.exception("Cloudflare® API Error")
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


def tfk_get_routers(config: MutableMapping) -> list[str]:
    """
    Query Traefik API for the list of the HTTP Routers

    :param config: Parsed config file
    :return: List of the HTTP Routers
    :rtype: list
    """
    api_route: str = "/api/http/routers"  # API Route to dump router config
    url: str = config["TRAEFIK"]["url"].rstrip("/") + api_route  # Create URL
    # If the endpoint is not under authentication
    if not config["TRAEFIK"]["auth"]:
        with requests.get(url) as api_query:
            api_query.raise_for_status()
            # Get the list of HTTP Routers
            tfk_routers: list[dict] = api_query.json()
            tfk_domains: list[str] = tfk_parse_routers(tfk_routers)
            return tfk_domains
    else:
        # Only HTTPBasicAuth is currently supported
        with requests.get(url, auth=HTTPBasicAuth(username=config["TRAEFIK"]["user"],
                                                  password=config["TRAEFIK"]["pass"])) as api_query:
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
    Extract, and syntaxically check the domain from the basic rule list

    :param host_rules: List of host rules
    :type host_rules: list[str]
    :return: List of domains extracted
    :rtype: list[str]
    """
    basic_domains: list[str] = []
    # Only those characters are allowed in domains, and domains can't start or end by either a "." or a "-"
    regex = re.compile(r"[a-z\d][a-z\d\-.]*[a-z\d]",
                       re.IGNORECASE | re.VERBOSE)
    for rule in host_rules:
        # Extract the domain name from rule
        basic_domains.append(rule.split("`")[1].lower())
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
    :type domains: list[str]
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
    :type tfk_subdomains: list[dict]
    :param cf_domains: List of all zones of the account
    :type cf_domains: list[dict]
    :param config: Parsed config file
    :type config: MutableMapping
    :return: Dictionnary comprising the crafted records
    :rtype: dict
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
                # If the subdomain is empty, it would break, due to the leading .
                zones_to_update[zone["name"]]["domains"].append(
                    f"{entry['subdomain']}.{entry['domain']}.{entry['suffix']}" if entry["subdomain"].isalnum()
                    else f"{entry['domain']}.{entry['suffix']}"
                )
    for zone in zones_to_update.keys():
        for domain in zones_to_update[zone]['domains']:
            if not ipv6:  # Only append A records if IPv6 is disabled
                zones_to_update[zone]['records'].append(
                    {
                        "name": domain,
                        "type": "A",
                        "content": ipv4,
                        'ttl': int(config["CLOUDFLARE"]["TTL"]),
                        'proxied': bool(config["CLOUDFLARE"]["proxied"])
                    }
                )
            else:  # Append both A and AAAA records
                zones_to_update[zone]['records'].append(
                    {
                        "name": domain,
                        "type": "A",
                        "content": ipv4,
                        'ttl': int(config["CLOUDFLARE"]["TTL"]),
                        'proxied': bool(config["CLOUDFLARE"]["proxied"])
                    }
                )
                zones_to_update[zone]['records'].append(
                    {
                        "name": domain,
                        "type": "AAAA",
                        "content": ipv6,
                        'ttl': int(config["CLOUDFLARE"]["TTL"]),
                        'proxied': bool(config["CLOUDFLARE"]["proxied"])
                    }
                )
    return zones_to_update


def cf_add_record(zones_to_update: dict[dict],
                  config: MutableMapping) -> None:
    """
    Posts records to CF

    :param zones_to_update: dict of dns records to add
    :type zones_to_update: dict[dict]
    :param config: Parsed config file
    :type config: MutableMapping
    :return: Nothing
    """
    try:
        cf_instance = CloudFlare.CloudFlare(
            token=config["CLOUDFLARE"]["api_token"])
    except CloudFlare.exceptions.CloudFlareAPIError as e:
        logger.exception(f"Cloudflare® API Error: {e}")
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
    Grabs Public IP from the config file

    :param config: List of credentials
    :return: ipv4 and ipv6 (address or disable switch)
    :rtype: tuple[str, str | bool]
    """
    # TODO: Integrate into initial parsing
    ipv4: str = ""
    ipv6: str | bool = ""
    try:
        if validators.ipv4(config["IP"]["IPv4"]):
            ipv4 = config["IP"]["IPv4"]
        else:
            logger.error("Missing or invalid IPv4, aborting")
            exit(139)
    except KeyError:
        logger.error("Missing configuration key for IPv4 aborting")
        raise
    try:
        if isinstance(config["IP"]["IPv6"], str) and validators.ipv6(config["IP"]["IPv6"]):
            ipv6 = config["IP"]["IPv6"]
        elif not config["IP"]["IPv6"]:
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
    """
    Asserts syntaxic validity of the config file when provided through the CLI

    Validity for file provided through config file is determined at parsing

    :param ctx: Click contect
    :param param: Click parameter
    :param value: Click parameter value
    :return: The given value if it is valid
    :raise click.BadParameter: If the config file fails to load
    """
    if value != g_config_file_name:
        try:
            _ = toml.load(open(value, "rt"))  # Try loading the config file
        except toml.decoder.TomlDecodeError as e:
            logger.exception(f"Decoding error on config file : {e}")
            raise click.BadParameter(f"Decoding error on config file : {e}")
        else:
            return value
    else:
        return value

# CLI


@click.group(context_settings=g_context_options)
@click.option('--debug/--no-debug', default=False, help="Enable debug mode")
@click.option("-c",
              "--config-file",
              type=click.Path(exists=True),
              callback=validate_config_file,
              default=g_config_file_name,
              required=False,
              show_default=True,
              help="Config file path")
@click.option("-l", "--license", "legal_print", is_flag=True, default=False, help="Print License")
@click.pass_context
def cli(ctx, debug, config_file, legal_print):
    """
    Syncs Traefik with CloudFlare DNS

    \f

    :param ctx: Click context
    :param debug: Enable regular debug mode
    :param config_file: Set a custom file path for the config file
    :param legal_print: Print license
    :type legal_print: bool
    :return:
    """
    if legal_print:
        click.echo(legal)
        exit(0)
    ctx.ensure_object(dict)
    ctx.obj["DEBUG"] = debug
    ctx.obj["CONFIG"] = config_file


@cli.command()
@click.option("-p/-P",
              "--post/--no-post",
              default=True,
              show_default=True,
              help="Post the records to Cloudflare®'s API")
@click.option("-e/-E",
              "--check-exists/--no-exists-check",
              default=True,
              show_default=True,
              help="Disable the checks against CF zones and force add records"
              )
@click.pass_context
def run(ctx, post, check_exists):
    """
    Run the script

    \f

    :param ctx: Click context
    :param post: Bypass of the post routines
    :type post: bool
    :param check_exists: Bypass of the existence checks
    :type check_exists: bool
    :return: Nothing
    """
    ctx.obj["POST"] = post
    ctx.obj["CHECK"] = check_exists
    main(ctx)


def main(ctx=None, c_config_file=g_config_file_name, c_check=True, c_post=False):
    """
    Main function that controls the running of the program

    :param ctx: Click context
    :param c_config_file: Function parameter for the config file path.
        This is not used if the context is provided (when the CLI is not used, for exemple in a python console)
    :type c_config_file: bool, optional
    :param c_check: Function parameter for the existence check.
        This is not used if the context is provided (when the CLI is not used, for exemple in a python console)
    :type c_check: bool, optional
    :param c_post: Function parameter for the CloudFlare's post.
        This is not used if the context is provided (when the CLI is not used, for exemple in a python console)
    :type c_post: bool, optional
    :return: Nothing
    """
    logger.info("Starting up tcfig")
    if ctx is not None:
        config = parse_config(ctx.obj["CONFIG"])  # Parse config file
    else:  # If CLI is not ran, context will not be available
        config = parse_config(c_config_file)
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
    if (ctx is not None and ctx.obj["CHECK"]) or (ctx is None and c_check):
        logger.info("Checking for record existence")
        tfk_subdomains_verified = cf_check_existence(
            cf_domains_verified, tfk_subdomains_verified, config)  # Check what subdomains are to be added
    if len(tfk_subdomains_verified) < 1:  # If nothing to do
        logger.info("Nothing to do, exiting")
        exit(0)
    records = gen_records(
        tfk_subdomains_verified, cf_domains_verified, config)  # Generate records
    if (ctx is not None and ctx.obj["POST"]) or (ctx is None and c_post):
        logger.info("Posting to Cloudflare®")
        cf_add_record(records, config)  # Add records to Cloudflare®
    else:
        logger.info("CloudFlare post routine bypassed")
        exit(0)


if __name__ == '__main__':
    cli(obj={})
