# Firepower Management Center - Dynamic Object Updater

This code repository contains a script to automatically update FMC dynamic objects using information from a DNS zone transfer.

This script will:
 - Request zone transfer from a provided DNS server
 - Query FMC dynamic objects to inspect current contents
 - Compare results to determine addresses to add/remove from FMC object
 - Modify FMC object to add/remove addresses

## Contacts
* Matt Schmitz (mattsc@cisco.com)

## Solution Components
* Cisco Firepower Management Center

## Installation/Configuration

**[Step 1] Clone repo:**
```bash
git clone <repo_url>
```

**[Step 2] Install required dependancies:**
```bash
pip install -r requirements.txt
```

**[Step 3] Configure required variables:**

Configure the following values within `fmc_dynamic_object_updater.py`:

```python
#######################
# Set FMC details & login credentials:
USERNAME = "<FMC USER>"
PASSWORD = "<FMC PASSWORD>"
FMC = "<FMC ADDRESS>"

# FMC Dynamic object name to domain name mappings
# Example:
#  DOMAIN_INFO = {"fmc_object_name": "corp_domain.local"}
DOMAIN_INFO = {
    "corp_domain_ip_list": "test.local",
    "lab_domain_ip_list": "lab.test.local",
}

# DNS server for zone transfer
NAMESERVER = "<NAMESERVER ADDRESS>"
#######################
```



## Usage

Run the script with `python3 fmc_dynamic_object_updater.py`

The script will then:
 - Request zone transfer information for each domain
 - Store all unique IP addresses for any DNS A records
 - Query FMC to locate matching dynamic objects
 - Store current contents of dynamic objects
 - Compare zone transfer data with current contents of dynamic object
 - Build list of addresses to add or remove from dynamic object
 - Push requested changes to FMC

# Screenshots

**Example of script execution:**

![/IMAGES/example_output.png](/IMAGES/example_output.png)


### LICENSE

Provided under Cisco Sample Code License, for details see [LICENSE](LICENSE.md)

### CODE_OF_CONDUCT

Our code of conduct is available [here](CODE_OF_CONDUCT.md)

### CONTRIBUTING

See our contributing guidelines [here](CONTRIBUTING.md)

#### DISCLAIMER:
<b>Please note:</b> This script is meant for demo purposes only. All tools/ scripts in this repo are released for use "AS IS" without any warranties of any kind, including, but not limited to their installation, use, or performance. Any use of these scripts and tools is at your own risk. There is no guarantee that they have been through thorough testing in a comparable environment and we are not responsible for any damage or data loss incurred with their use.
You are responsible for reviewing and testing any scripts you run thoroughly before use in any non-testing environment.