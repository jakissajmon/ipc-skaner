**```English```** | [```Polski```](/README.md)

## Unsecured Dahua IP Cameras SN scanner
> [!CAUTION]
> This software is PoC(Proof of Concept) for educational purposes only. Me or any contributors are not responsible for any damages done using this software. 

This software looks for unsecured **Dahua** cameras, generating a file with the Serial Number, and the default password `admin`, which can be imported into [SmartPSS](https://dahuawiki.com/SmartPSS) or [SmartPSS Lite](https://dahuawiki.com/SmartPSS_Lite). It's based on a Portuguese scanned from Discord(unknown author).
**Not all generated cameras will work. Some have other passwords, some are off or not configured. It's random.**

More info in my [Discord](https://discord.gg/eF9wWm3ufU).

### Requirements
* Install Python: `winget install python`
* Install "xmltodict": `py -m pip install xmltodict`

### How to use?
**You can view all commands with `py skaner.py -h`. The commands below are just examples.**

* To use interactive settings, use `py skaner.py -i -f (file)`.
* To scan using one random prefix from a file use `py skaner.py -r -f (file)`.
* To scan will all prefixes from a file use `py skaner.py -ma -f (file)`.
* To change the amount of threads, use `-t (number)`.

> [!WARNING]
> The number of threads should be adjusted to the speed of your internet - otherwise it may lead to a crash/significant slowdown.

**Important:**
* prefix(/ks) - first 10 characters of a SN;
* suffix(/ks) - last 5 characters of a SN
