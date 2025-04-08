# GetAllResources.ps1

This script is going through all visible subscriptions and generating inventory.

## Description

This script retrieves an inventory of Azure resources across all visible subscriptions in your account. It generates detailed reports, including resource hierarchies, assigned roles, public IPs, URLs, operating systems, and programming languages. The script uses your current Azure session to access and list only the resources visible to you.

## Usage

- Start powershell console
- Navigate to folder where script is located
- ./GetAllResources.ps1

## Output

Results are stored in multiple files.

* "azure-inventory-\<tenant-id\>.txt"
  * Contains list of items viewed as tree
  * Subscription >> Resource groups >> Resource >> Interesting details
  * It's listing only items which are visible for you, because it's using your session
 
* "azure-roles-\<tenant-id\>.csv"
  * Contains list of roles directly assigned to people, groups and managed identities
  * Roles assigned via management groups or inherited are not included, so that's why you could check what's really assigned to exact resource.

* "azure-ips-\<tenant-id\>.csv"
  * List of public IPs used at components
  * List could be used for pentesting or scanning

* "azure-urls-\<tenant-id\>.csv"
  * List of URLs used at components
  * List could be used for testing of vulnerabilities

* "azure-osystems-\<tenant-id\>.csv" 
  * List of OS and versions

* "azure-languages-\<tenant-id\>.csv"
  * List of used programming languages
