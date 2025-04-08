# Auditing / Resources

Collection of scripts for auditing subscriptions, resource groups, and resources within a tenant.
Auditing and detailing are optional features. The basic functionality involves listing all items within the tenant and creating an inventory based on a tree view.
## GetAllResources.ps1

This script is going through all visible subscriptions and generating inventory. 

Result is stored at many different files.

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

* "azure-audit-\<tenant-id\>.csv" 
  * Result of deeper audit

* "azure-osystems-\<tenant-id\>.csv" 
  * List of OS and versions

* "azure-languages-\<tenant-id\>.csv"
  * List of used programming languages

