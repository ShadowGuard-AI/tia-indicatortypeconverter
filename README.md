# tia-IndicatorTypeConverter
Converts indicators between different formats (e.g., IP address to CIDR, domain to URL) using the `netaddr` library. Input from stdin, output to stdout. - Focused on Aggregates threat intelligence data from various open-source feeds and web pages (e.g., vulnerability databases, security blogs, Twitter feeds) into a unified format for analysis and alerting. Allows for filtering and correlation of threat indicators. Focus is on collecting and structuring existing intelligence, not generating new intelligence.

## Install
`git clone https://github.com/ShadowGuardAI/tia-indicatortypeconverter`

## Usage
`./tia-indicatortypeconverter [params]`

## Parameters
- `-h`: Show help message and exit
- `-t`: The type of conversion to perform.
- `-s`: No description provided
- `-i`: The input string. If not provided, reads from stdin.

## License
Copyright (c) ShadowGuardAI
