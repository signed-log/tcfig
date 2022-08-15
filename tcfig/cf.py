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


class CF:
    def __init__(self, config: typing.MutableMapping):
        self.config = config if self.check_credentials() else None
        self.cf_instance = CloudFlare.CloudFlare(
            token=config["CF"]["api_token"])

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
    def cf_get_zones(self) -> typing.Tuple[typing.List[dict], typing.List[dict]]:
        """
        Query Cloudflare API and export the zones of the account

        :param config: Credentials given by `get_credentials`
        :return: List of the zones
        :rtype: list
        """
        try:
            # Get the zone list
            cf_zone_list: typing.List[dict] = self.cf_instance.zones.get()
        except CloudFlare.CloudFlareAPIError:
            logger.exception(
                "Cloudflare API Error, your token is likely invalid")
            raise
        # Returns the zone list
        if len(cf_zone_list) < 1:
            logger.error("No zones on CF found")
            exit(121)
        cf_domains: typing.List[dict] = self.cf_parse_zones(cf_zone_list)
        return cf_zone_list, cf_domains

    @staticmethod
    def cf_parse_zones(cf_zone_list: typing.List[dict]) -> typing.List[typing.Dict]:
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
                logger.warning(
                    f" DNS zone for domain {zone['name']} isn't active")
                continue
            if "#dns_records:edit" not in zone['permissions']:
                logger.warning(
                    f"DNS Record editing permissions lacking for zone {zone['name']}")
                continue
            cf_domains.append({'id': zone["id"], 'name': zone["name"]})
        if len(cf_domains) < 1:
            logger.error("No active domains found")
        return cf_domains

    @staticmethod
    def cf_check_tld_existence(cf_domains: typing.List[dict], tfk_subdomains: typing.List[dict]) \
            -> typing.Tuple[list[dict], list[dict]]:
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

    def cf_check_existence(self, cf_domains: typing.List[dict], tfk_subdomains: typing.List[dict]) -> typing.List[dict]:
        """
        Check if any subdomains are already in the zone

        :param cf_domains: List of domains in the CF's user zone along with the zone ID
        :type cf_domains: list[dict]
        :param tfk_subdomains:
        :param config: Credentials file
        :return: Computed domains not in CF
        """
        # Query a dump of the DNS zones
        dns_records = [self.cf_instance.zones.dns_records.get(
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
