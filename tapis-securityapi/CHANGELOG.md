# Change Log for Tapis Security Kernel

All notable changes to this project will be documented in this file.

Please find documentation here:
https://tapis.readthedocs.io/en/latest/technical/security.html

You may also reference live-docs based on the openapi specification here:
https://tapis-project.github.io/live-docs

-----------------------
## 1.7.1 - 2024-10-24

### New Features:
1. Add support for managing system secrets with KeyType = tmskey.

-----------------------
## 1.7.0 - 2024-09-17

### New Features:
1. Release number change.

-----------------------
## 1.6.3 - 2024-09-04

### New Features:
1. Updated shared library.

-----------------------
## 1.6.2 - 2024-05-19

### New Features:
1. Update maven repository reference.
2. Define non-root image in Dockerfile.

-----------------------
## 1.6.1 - 2024-02-28

### New Features:
1. Recursive query optimization using new sk_roles.has_children column.

### Bug fixes:
1. Fix ambiguous column reference. 

-----------------------
## 1.6.0 - 2024-01-24

### New Features:
1. Increment release number.

-----------------------
## 1.5.10 - 2023-11-20

### Bug fixes:
1. Rebuild with latest shared code to fix JWT validation issue.

-----------------------
## 1.5.1 - 2023-10-31

1. Added more logging during password validation.

-----------------------
## 1.5.0 - 2023-10-06

### New features:
Tapis 1.5.0 release.

-----------------------
## 1.4.0 - 2023-07-17

### New features:
Tapis 1.4.0 release.

-----------------------
## 1.3.2 - 2023-05-04

Automatically assign tenant_definition_update role to tokens service at primary site.

-----------------------
## 1.3.1 - 2023-04-03

Increase SkAdmin secrets timeout from 1 to 10 seconds in Kubernetes.

-----------------------
## 1.3.0 - 2023-03-03

Maintenance release

-----------------------
## 1.2.4 - 2023-02-07

### New features:
Initial Globus support.

-----------------------
## 1.2.3 - 2022-09-22

SKExport implemented.

-----------------------

## 1.2.2 - 2022-08-23

Maintenance release

-----------------------

## 1.2.1 - 2022-07-25

Maintenance release

### Breaking Changes:

### New features:
1. Updated 3rd party libraries

### Bug fixes:

-----------------------

## 1.2.0 - 2022-05-31

Maintenance release

### Breaking Changes:
- Add grantor to create share request.

### New features:

### Bug fixes:
1. Fix syntax error in generated SQL clause on create share. 

-----------------------

## 1.1.3 - 2022-05-09

SK Sharing APIs

### Breaking Changes:
- none.

### New features:
1. Adjust JVM memory options and other deployment file clean up.
2. Improve JWT validation and authentication logging.
3. Implement new SK Sharing APIs including required DB schema changes.

-----------------------

## 1.1.2 - 2022-03-04

Java 17 upgrade

### Breaking Changes:
- none.

### New features:
1. Upgrade code and images to Java 17.0.2.

-----------------------

## 1.1.1 - 2022-02-01

No changes

-----------------------

## 1.1.0 - 2022-01-07

New minor release, no changes.

-----------------------

## 1.0.5 - 2021-12-09

Bug fix release

### Breaking Changes:
- none.

### New features:
1. Improved getUserPerm endpoint livedocs documentation.

### Bug fixes:
1. Removed duplicate code.

-----------------------

## 1.0.3 - 2021-10-12

Bug fix release

### Breaking Changes:
- none.

### Bug fixes:
1. Fix version in non-standard POM files.

-----------------------

## 1.0.0 - 2021-07-16

Initial release supporting basic CRUD operations on Tapis authorization 
and secrets resources.

1. Authorization engine based on an extension of Apache Shiro semantics.
2. Authorization API for roles, permissions and users.
3. Secret support using Hashicorp Vault backend.
4. Secrets API with custom handling of system, database credentials, JWT signing keys
   service password and user secret types.

### Breaking Changes:
- Initial release.

### New features:
 - Initial release.

### Bug fixes:
- None.
