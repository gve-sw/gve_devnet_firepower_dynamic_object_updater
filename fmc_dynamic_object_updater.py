"""
Copyright (c) 2022 Cisco and/or its affiliates.
This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at
               https://developer.cisco.com/docs/licenses

All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
"""

import json
import sys

import dns.resolver
import dns.zone
import requests
from requests.api import get, post, put
from requests.auth import HTTPBasicAuth
from requests.models import Response
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from rich.console import Console
from rich.panel import Panel

console = Console()

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

#######################
# Set FMC details & login credentials:
USERNAME = ""
PASSWORD = ""
FMC = ""

# FMC Dynamic object name to domain name mappings
# Example:
#  DOMAIN_INFO = {"fmc_object_name": "corp_domain.local"}
DOMAIN_INFO = {
    "": "",
    "": "",
}
#######################

PLATFORM_URL = "https://" + FMC + "/api/fmc_platform/v1"
CONFIG_URL = "https://" + FMC + "/api/fmc_config/v1"


class FirePower:
    def __init__(self):
        """
        Initialize the FirePower class, log in to FMC,
        and save authentication headers
        """
        with requests.Session() as self.s:
            console.print(f"Attempting login to {FMC}")
            self.authRequest()

            self.headers = {
                "Content-Type": "application/json",
                "X-auth-access-token": self.token,
            }

    def authRequest(self):
        """
        Authenticate to FMC and retrieve auth token
        """
        authurl = f"{PLATFORM_URL}/auth/generatetoken"
        resp = self.s.post(authurl, auth=(USERNAME, PASSWORD), verify=False)
        if resp.status_code == 204:
            # API token, Refresh token, default domain, and
            # other info returned in HTTP headers
            console.print("[green][bold]Connected to FMC.")
            # Save auth token & global domain UUID
            self.token = resp.headers["X-auth-access-token"]
            self.global_UUID = resp.headers["DOMAIN_UUID"]
            console.print(f"\nGlobal domain UUID: {self.global_UUID}")
            return
        else:
            console.print("[red]Authentication Failed.")
            console.print(resp.text)
            sys.exit(1)

    def getDynamicObjects(self):
        """
        Function to retrieve all dynamic objects in FMC.
        Builds dictionary of dynamic object names to UUIDs.
        """
        console.print("Querying FMC...\n")
        url = f"{CONFIG_URL}/domain/{self.global_UUID}/object/dynamicobjects"
        resp = self.getData(url)
        if resp:
            resp_json = json.loads(resp)
            self.dynamicObjects = {}
            # Read each dynamic object in FMC & look for matching name in DOMAIN_INFO
            for object_name in DOMAIN_INFO.keys():
                domain_name = DOMAIN_INFO[object_name]
                for obj in resp_json["items"]:
                    if obj["name"] == object_name:
                        console.print(
                            f"[green]Found[/green] {object_name} UUID: {obj['id']}"
                        )
                        self.dynamicObjects[domain_name] = obj["id"]
                if domain_name not in self.dynamicObjects:
                    console.print(f"[red]{object_name} not found in FMC.")
                    self.dynamicObjects[domain_name] = None

    def getDynamicObjectContents(self):
        """
        Function to retrieve the contents of a dynamic object
        """
        console.print("Querying FMC...")
        # Build list of object name to list of IPs in dynamic object
        self.current_mapping = {}
        for domain_name in self.dynamicObjects:
            # Match up current domain name & UUID to object name
            for object, domain in DOMAIN_INFO.items():
                if domain == domain_name:
                    object_name = object
                    break

            uuid = self.dynamicObjects[domain_name]
            self.current_mapping[domain_name] = []
            console.print(f"\nGetting object details for: {object_name}")
            # If no UUID - then we didn't find the object earlier. So skip it.
            if uuid is None:
                console.print("[yellow]No UUID - Skipping...")
                self.current_mapping[domain_name] = None
                continue
            # Pull all dynamic object IPs, limit to 500
            url = f"{CONFIG_URL}/domain/{self.global_UUID}/object/dynamicobjects/{uuid}/mappings?limit=500"
            resp = self.getData(url)
            if resp:
                resp_json = json.loads(resp)
                try:
                    # Add IPs in current mapping to list
                    for mapping in resp_json["items"]:
                        self.current_mapping[domain_name].append(mapping["mapping"])
                    console.print(
                        f"[green]Found[/green] {len(self.current_mapping[domain_name])} existing IP addresses."
                    )
                except KeyError:
                    # FMC returns no list if the object exists, but is empty
                    console.print("[yellow]Dynamic object is empty.")
                    self.current_mapping[domain_name] = None
            if not resp:
                # If we got a 404 trying to retrive object, then it doesn't exist
                console.print(f"[red]Error retrieving dynamic object.")
                self.current_mapping[domain_name] = None
        return self.current_mapping

    def updateDynamicObject(self, mapping, action):
        """
        Function to modify the contents of a dynamic object
        """
        for domain_name in mapping:
            # Skip if no IPs in mapping list
            if not mapping[domain_name]:
                console.print(f"[yellow]No IP addresses to modify for {domain_name}")
                continue
            uuid = self.dynamicObjects[domain_name]
            # Skip if we have no UUID, meaning we didn't find the object earlier
            if uuid is None:
                console.print("[yellow]No UUID - Skipping...\n")
                self.current_mapping[domain_name] = None
                continue
            console.print(f"Updating addresses for {domain_name}")
            url = f"{CONFIG_URL}/domain/{self.global_UUID}/object/dynamicobjects/{uuid}/mappings?action={action}"
            payload = {"mappings": mapping[domain_name]}
            self.putData(url, payload)
            console.print(
                f"[green]Updated {len(mapping[domain_name])} addresses on dynamic object.\n"
            )

    def getData(self, get_url):
        """
        General function for HTTP GET requests with authentication headres
        """
        # console.print(f"Sending GET to: {get_url}")
        resp = self.s.get(get_url, headers=self.headers, verify=False)
        if resp.status_code == 200:
            return resp.text
        if resp.status_code == 404:
            return None
        else:
            console.print("[red]Request FAILED. " + str(resp.status_code))
            console.print(resp.text)

    def putData(self, put_url, put_data):
        """
        General function for HTTP POST requests with authentication headers & some data payload
        """
        # console.print(f"Sending PUT to: {post_url}")
        resp = self.s.put(put_url, headers=self.headers, json=put_data, verify=False)
        # 201 returned for most successful object creations
        if resp.status_code == 201:
            return resp.text
        # 202 is returned for accepted request
        if resp.status_code == 202:
            return resp.text
        else:
            console.print("[red]Request FAILED. " + str(resp.status_code))
            console.print(resp.text)
            console.print(put_data)


##############################
#  General Functions
##############################


def dns_zone_xfer():
    """
    Query domain for zone transfer

    Return all IP addresses for any A records
    """
    domain_addresses = {}
    for domain in DOMAIN_INFO.values():
        domain_addresses[domain] = []

        console.print(f"  -- Processing {domain} --")

        # Find nameservers
        console.print(f"Locating nameservers...")
        try:
            ns = [server for server in dns.resolver.resolve(domain, "NS")]
            console.print(f"Found {len(ns)} nameservers.")
        except dns.resolver.NXDOMAIN:
            console.print("[red]NXDOMAIN - Domain not found.")
            continue
        for nameserver in ns:
            # Get nameserver ip
            ip_list = dns.resolver.resolve(nameserver.target, 'A')
            # Attempt zone transfer
            for ip in ip_list:
                console.print(f"Attempting zone transfer from {nameserver}...")
                try:
                    z = dns.zone.from_xfr(dns.query.xfr(ip.to_text(), domain))
                    console.print("[green]Zone transfer successful.")
                except:
                    console.print("[red]Zone transfer failed or refused.")
                    continue
                # Iterate through all records in the zone, pull out A records
                for _, _, rdata in z.iterate_rdatas("A"):
                    # Append all IP addresses to list / check for duplicates
                    if rdata.to_text() not in domain_addresses[domain]:
                        domain_addresses[domain].append(rdata.to_text())
        console.print(
            f"[green]Finished:[/green] Collected {len(domain_addresses[domain])} unique IP addresses.\n"
        )
    return domain_addresses


def compareResults(zone_transfer, current_mapping):
    """
    Compare two lists of IP addresses to find which match & which don't
    """
    addresses_to_add = {}
    addresses_to_remove = {}

    for domain in zone_transfer:
        addresses_to_add[domain] = []
        addresses_to_remove[domain] = []

        console.print(f"  -- Processing {domain} --")
        # If no current mapping or zone transfer, skip
        if not current_mapping[domain] and not zone_transfer[domain]:
            console.print(f"[yellow]No data. Skipping...\n")
            continue

        # If current dynamic object is empty, add all IP addresses from zone transfer
        # and none need to be removed
        if not current_mapping[domain]:
            console.print(f"No IPs currently mapped to dynamic object for {domain}.")
            console.print(f"{len(zone_transfer[domain])} IPs will be added.\n")
            addresses_to_add[domain] = zone_transfer[domain]
            addresses_to_remove[domain] = None
            continue

        # If zone transfer contains addresses that are not in current mapping, add them to list
        for each in zone_transfer[domain]:
            if each not in current_mapping[domain]:
                addresses_to_add[domain].append(each)
        console.print(
            f"{len(addresses_to_add[domain])} new IP addresses will be [green]added[/green]"
        )

        # If current mapping contains addresses that are not in zone transfer, remove them from list
        for each in current_mapping[domain]:
            if each not in zone_transfer[domain]:
                addresses_to_remove[domain].append(each)
        console.print(
            f"{len(addresses_to_remove[domain])} old IP addresses will be [red]removed[/red]"
        )
        console.print("")

    return addresses_to_add, addresses_to_remove


def main():
    """
    Main flow of script execution
    """
    console.print("")
    console.print(Panel.fit("  -- Start --  "))
    console.print("")

    console.print("")
    console.print(Panel.fit("Zone Transfer", title="Step 1"))
    zone_transfer = dns_zone_xfer()

    console.print("")
    console.print(Panel.fit("Connect to FMC", title="Step 2"))
    fmc = FirePower()

    console.print("")
    console.print(Panel.fit("Find Dynamic Object UUID", title="Step 3"))
    fmc.getDynamicObjects()

    console.print("")
    console.print(Panel.fit("Get Current Mappings", title="Step 4"))
    current_mapping = fmc.getDynamicObjectContents()

    console.print("")
    console.print(Panel.fit("Compare Results", title="Step 5"))
    add, remove = compareResults(zone_transfer, current_mapping)

    console.print("")
    console.print(Panel.fit("Add New IP Addresses", title="Step 6"))
    fmc.updateDynamicObject(add, "add")

    console.print("")
    console.print(Panel.fit("Remove Old IP Addresses", title="Step 7"))
    fmc.updateDynamicObject(remove, "remove")

    console.print("")
    console.print(Panel.fit("  -- Finished --  "))
    console.print("")


if __name__ == "__main__":
    main()
