# -*- coding: utf-8 -*-
import CloudFlare


class CF:
    def __init__(self, cf_token):
        self.cf_instance = CloudFlare.CloudFlare(token=cf_token)

    def get_zones(self, raw=False, permissions_to_check=None):
        cf_zone_list = self.cf_instance.zones.get()
        if raw:
            return cf_zone_list
        for zone in cf_zone_list:
            if zone['status'] != "active":
                continue
