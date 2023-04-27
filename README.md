# domain-monitor

A domain name expiry monitoring tool written in PHP, which can output HTML reports designed for sending via email.

This is ideal for sending weekly domain name expiry reminders to your IT infrastructure/security team mailboxes, or just for keeping track of your personal domain names.

### Example Report

```
Hi,

There are 2 domain name renewals requiring action within the next 28 days:

[Domain Name]   [Expiry Date]
example.com     2019-07-25 (21 days)
example.org     2019-07-26 (22 days)

There is another 1 domain name renewal requiring action within the next 90 days:

[Domain Name]   [Expiry Date]
example.net     2019-08-08 (34 days)

In addition, there are 37 domain names not yet due for renewal, and a total of 40 domain names in the monitoring list.

Thank you,
Domain Monitor
```

### Contents

* [Introduction](#domain-monitor)
* [Changelog](#changelog)
* [Command-line Arguments](#command-line-arguments)
* [Setup Guide](#setup-guide)
  * [System Environment](#system-environment)
  * [Dependencies](#dependencies)
  * [Downloading the Program](#downloading-the-program)
  * [Verifying the Integrity of the Download](#verifying-the-integrity-of-the-download)
    * [Packaged Release](#packaged-release)
    * [Git Repository](#git-repository)
  * [Configuration File](#configuration-file)
  * [Domain Name List](#domain-name-list)
  * [Generating Your First Report](#generating-your-first-report)
  * [Sending Email](#sending-email)
    * [Sending Email Using `s-nail` on Linux](#sending-email-using-s-nail-on-linux)
    * [Sending Email Using `Send-MailMessage` in PowerShell on Windows 10/Server 2016](#sending-email-using-send-mailmessage-in-powershell-on-windows-10server-2016)
* [License and Disclaimer](#license-and-disclaimer)
* [Feedback](#feedback)

## Changelog

| Date | Notes |
|------|-------|
| **2019-12-31** | Fixed bug related to expiry date checks for `gov.uk` domains where partial WHOIS responses were returned (#40). |
| **2019-09-25** | Improved handling of missing `head.txt` file. Minor code improvements and README adjustments. |
| **2019-09-13** | Initial public release. Added license and updated README. |
| **2019-09-12** | Headers are no longer prepended by default, so removed `--no-headers` and added `--smtp-headers`. Code quality improvements. |
| **2019-08-30** | Switched config file format to `.ini`. Added validation of config file parameters. Added `custom_name` config parameter to allow setting a custom/branded name for Domain Monitor. Other minor refactoring and adjustments. |
| **2019-08-28** | Added `--directory` to allow for manually overriding the working directory of the program. Domains removed from the monitoring list are now removed from the report as well. Other minor refactoring and improvements. |
| **2019-08-14** | Added `--no-headers`, `--full` to report command, added `--all` to update command, added `--help`, general refactoring and improvements. |
| **2019-07-29** | Added checking for duplicate domains in the domains list. |
| **2019-07-11** | Added support for gov.uk domains, numerous bug fixes and improvements. |
| **2019-07-09** | Implemented config file for user-configurable options. |
| **2019-06-26** | Removed obsolete email code, raw email headers are now outputted directly at the top of the report, so it's ready to be sent via SMTP. |
| **2019-02-14** | Fixed domains expiring today showing as `-0 days`, fixed excessive log output when a connection to the WHOIS server cannot be made. |
| **2019-01-03** | Initial internal release. |
| **2018-12-24** | Development started. |

## Command-line Arguments

* `update <int>`: Update *int* expiry dates (e.g. `update 3` will re-check the expiry date for 3 domains)
* `update all`: Update **all** expiry dates (may cause you to hit WHOIS server rate limits)
* `report`: Output a 90 day domain name expiry report.
* `report --full`: Output a full domain name expiry report.
* `report --smtp-headers`: Output a domain name expiry report with prepended email headers.

## Setup Guide

### System Environment

Domain Monitor is written using PHP, so it can run anywhere that PHP can (Linux, BSD, macOS, Windows, etc).

The program will output reports/logs to `stdout`, so it's recommended to run the program in a shell that allows you to view, capture and redirect this output, such as Bash or PowerShell.

Network access to TCP port 43 (WHOIS) is required, as this is how the domain name expiry date checks are performed.

### Dependencies

* PHP 7.2 or above

### Downloading the Program

You can acquire the latest stable version of the program from the 'Releases' page, packaged in ZIP format.

Alternatively, you can `git clone` the repository to get the absolute latest version:

    $ git clone https://gitlab.com/jamie-cyc/domain-monitor.git

### Verifying the Integrity of the Download

It is recommended to perform an integrity check on the program before running it, to gain a level of assurance that it hasn't been tampered with or corrupted.

#### Packaged Release (Work in Progress)

Each packaged release from the 'Releases' page includes a detached GPG signature from the GPG key `F3E894B80EA90BAC998D406C46255AA2FB25278D [Jamie Scaife (Git Signing Key) <jamie-git@york.gov.uk>]`.

You can verify the detached signatures by importing the public key, and running `gpg --verify signature.asc domain-monitor.zip`.

#### Git Repository

Every commit in the repository is signed using GPG key `F3E894B80EA90BAC998D406C46255AA2FB25278D [Jamie Scaife (Git Signing Key) <jamie-git@york.gov.uk>]`.

You can view/verify these signatures by importing the public key, and running `git log --show-signature`.

### Configuration File

Before running the program, you will need to create and populate the configuration file.

Copy the example configuration file (`config.ini.example`) to `config.ini`. Each value that you need to configure is annotated as required.

### Domain Name List

You must also provide a list of domain names to monitor in the `domains.txt` file, one per line.

For example:

```
example.com
example.org
example.net
```

### Generating Your First Report

Reports produced by the program do not actively fetch every expiry date when they are generated, as this would possibly result in you hitting WHOIS server rate limits. Instead, expiry dates are checked separately using the 'update' functionality and stored in a JSON file, which is then used as the data source for the report.

First, you'll need to update the recorded expiry dates for some of the domains in `domains.txt`:

    $ php domain-mon.php update 5

The integer (`5` in this case) specifies how many records to update. This is to help avoid hitting WHOIS server rate limits. You can also use `update all` if you wish.

If you specify a number higher than the number of domains in your `domains.txt` file, the program will reduce this back to the total number of domains in the list.

The current position that the program is at in the `domains.txt` list will be stored in the file `head.txt`. This is to allow the program to check a large list of domains. For example, if you check 3 domains, the 'head' will move forward by 3, meaning that next time you check 3 domains, it will continue where it left off, rather than going back to the start of the list.

The file `expiries.json` will be used to store the expiry dates for the domain names. This file is used to generate the report.

Now you can generate a report:

    $ php domain-mon.php report

The report is generated in HTML format, optionally with email headers included at the top. The output is ready to be sent via email or displayed in a web browser.

### Sending Email

Domain Monitor does not have built-in functionality to send the email messages that it produces. This is to reduce dependencies and help ensure compatibility with as many different systems/environments as possible.

Instead, you should use your system's built-in functionality for sending email, such as `s-nail` on Linux or `Send-MailMessage` in PowerShell on Windows.

#### Sending Email Using `s-nail` on Linux

The `s-nail` program can be used to send email via a local or remote SMTP server.

On Debian-based Linux systems, you can install `s-nail` using:

    $ sudo apt install s-nail

In order to send a report, first write a report to `report.html`:

    $ php domain-mon.php report > report.html

Then you can send this via email. Configure the parameters below as required:

    $ cat report.html | s-nail -v -r "sender@example.test" -s "Domain Name Expiry Report for `date`" -S mta="smtp://mail.example.test" -S smtp-use-starttls recipient@example.test

By default, this will use anonymous authentication. If you want to specify a username and password, you'll need to enable `v15-compat` mode, by adding the `-S v15-compat` parameter, and then specify the username and password in the SMTP address, for example:

    -S v15-compat -S mta="smtp://username:password@mail.example.test"

#### Sending Email Using `Send-MailMessage` in PowerShell on Windows 10/Server 2016

The `Send-MailMessage` cmdlet can be used to send email via a local or remote SMTP server.

Firstly, write a report to `report.html`:

    PS> php domain-mon.php report > report.html
    
Then you can send this via email. Configure the parameters below as required:

    PS> Send-MailMessage -To "recipient@example.test" -From "sender@example.test" -Subject "Domain Name Expiry Report for $(date)" -SmtpServer "mail.example.test" -UseSsl -Body (Get-Content .\report.html | Out-String)

By default this will authenticate using the Windows account that you're currently logged in as. If you need to specify different credentials, you can do this with the `-Credential` option.

If you need to use the `Anonymous` account to authenticate to a local mail relay, use the following:

    PS> $anon = New-Object System.Management.Automation.PSCredential("anonymous", (ConvertTo-SecureString "anonymous" -AsPlainText -Force))

Then append `-Credential $anon` to the `Send-MailMessage` line above.

### Scheduler Setup

An optimum setup for Domain Monitor is to run the 'update' functionality every 10 minutes to fetch and store the expiry date for 1 domain, then run a report at the end of each day/week. This will provide up-to-date data, without hitting WHOIS server rate limits.

You can use a task scheduling utility such as Cron or Windows Task Scheduler to automate the running of Domain Monitor.

## License and Disclaimer

Domain Monitor is made available under the MIT License, meaning that you are permitted to freely use, share and modify the code, including for commercial purposes.

No warranty or service level agreements are provided. The code and packaged releases are provided on a good-will basis.

It is recommended to also have additional expiry monitoring in place for your domain names, for example automated reminder emails from the registrar.

## Feedback

Please feel free to submit bug reports using the GitLab issues system. All merge requests will be considered too.

Thank you!