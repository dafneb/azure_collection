# Auditing / Resources

Collection of scripts for auditing of subscriptions / resource groups / resources at tenant. 

Auditing and detailing is optional feature. Basic functionality is listing everything what is inside tenant and create inventory list based on tree view.

## GetAllResources.ps1

This script is going through all visible subscriptions and generating inventory. 

Result is stored at many different files.

* "azure-inventory-\<tenant-id\>.txt"
  * Contains list of items viewed as tree
  * Subscription >> Resource groups >> Resource >> Interesting details
  * It's listing only items which are visible for you, because it's using your session
 
* "azure-roles-\<tenant-id\>.csv"
  * Contains list of roles directly assigned to people, groups and managed identities
  * Roles assigned via managed groups or inherited are not included

* "azure-ips-\<tenant-id\>.csv"
  * List of public IPs used at components
  * List could be used for pentesting or scanning

* "azure-urls-\<tenant-id\>.csv"
  * List of URLs used at components
  * List could be used for testing of vulnerabilities

* "azure-audit-\<tenant-id\>.csv" 
  * Result of deeper audit

* "azure-osystems-\<tenant-id\>.csv" 
  * List of OS and versions

* "azure-languages-\<tenant-id\>.csv"
  * List of used programming languages

