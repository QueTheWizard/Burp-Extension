# **Secrets Sniffer**

[![Build status](https://github.com/QueTheWizard/Burp-Secrets-Sniffer/workflows/Build/badge.svg)](https://github.com/QueTheWizard/Burp-Secrets-Sniffer/actions?query=workflow%3ABuild)

Secrets Sniffer is a BurpSuite extension that passivly scans all HTTP responses in Burp and looks for sensitive information (such as Google API key, AWS access keys, Slack API keys, etc.) in them.

**Usage:**  
Just load the extension (JAR file) via Burp's Extender.

**Example finding:** 
![2021-08-19_16-43-23](https://user-images.githubusercontent.com/20052885/130079537-c0072767-87a7-4d39-ad8a-d04a6974a6eb.png)

