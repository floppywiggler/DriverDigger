# DriverDigger
A portable Windows kernel driver extraction tool


# Overview

DriverDigger is a portable Windows kernel driver extraction tool designed to assist in vulnerability research by collecting kernel drivers from a system. 
It enables researchers to efficiently gather non-Microsoft drivers, which are often more susceptible to security flaws and less scrutiny.

I created this project because I needed a way to build a repository of kernel drivers from different devices I had accessible without having to rely on manual extraction or painstakingly download drivers from online resources.

This tool ideal if you simply want to gather all the third-party drivers availbe on your existing windows system.

# Features

- Extracts all .sys driver files from the system.

- Filters out Microsoft-developed drivers to focus on third-party vendors. We do not exclude based on digital signatures since many vendors will still have a Microsoft Signed Signature on their kernel driver.

- Supports optional vendor-based filtering to extract drivers from a specific company/vendor.

- Provides an option to exclude known vulnerable drivers based on the latest loldrivers.io database. (Note: This is a simple filtering done on **filename**. A hash comparison would be better and might be implemented in the future)

- Downloads the latest vulnerability database (from loldrivers.io) dynamically to ensure up-to-date filtering.

- Generates a detailed CSV of extracted drivers, including path, vendor, and digital signature details.

## Why Skip Microsoft Drivers?

Microsoft drivers are typically better written and undergo rigorous security reviews, making them less likely to contain easy-to-exploit vulnerabilities. The goal of this tool is to focus on third-party drivers, where security misconfigurations and weak implementations are more common, making them a more promising target for vuln research.

## Usage

Command-Line Options

```
DriverDigger.exe [options]

Options:
  -h, --help          Display this help message.
  --vendor <vendor>   Only extract drivers whose CompanyName contains the specified vendor (case-insensitive).
  --vuln-exclude      Enable vulnerability exclusion. When this option is provided, the tool auto-downloads the latest CSV from loldrivers.io and uses it to skip drivers known to be vulnerable.

```
### Examples

Extract all non-Microsoft drivers on your system:

`DriverDigger.exe`

Extract only Intel drivers:

`DriverDigger.exe --vendor intel`

Exclude known vulnerable drivers:

`DriverDigger.exe --vuln-exclude`


## Output files

The application will create the following output files:

- "extracted_drivers/" folder will be created in the CWD. This is where the resulting drivers will be placed.
- "microsoft_drivers.txt": File that contains all the driver the application deems to be likely developed by Microsoft.
- "drivers_report.csv": File that contains all the drivers that was extracted and their information.
- "loldrivers.csv": If argument "--vuln-exclude" is passed, this is the file that will be downloaded from loldrivers and used for comparison on filenames to exclude from the final result.

## Limitations

1. The tool relies on file metadata to determine vendor information, which may be incomplete or inaccurate in some cases.

2. Some Microsoft drivers may not be correctly identified if their metadata does not explicitly state Microsoft as the vendor.

3. Requires administrative privileges to access system driver directories.

4. Filtering by vendor depends on the accuracy of the CompanyName field in the driver's version information.

5. Filtering on known vulnerable drivers relies on the filename alone. If the filename doesn't match (but the hash does), it won't be extracted.

## Intended Use

DriverDigger is designed for security researchers who need an efficient way to collect non-Microsoft kernel drivers for vulnerability research in bulk. It simplifies the process of gathering relevant drivers while allowing optional filtering and exclusion of known vulnerable ones to streamline analysis and to avoid targeting drivers already known to be vulnerable.

## Disclaimer

This tool is intended for security research and vulnerability analysis. Use it responsibly and ensure compliance with all applicable laws and regulations when handling extracted drivers. Author of this project is not responsible for any misuse

