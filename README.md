# tia-IndicatorTypeConverter
Converts indicators between different formats (e.g., IP address to CIDR, domain to URL) using the `netaddr` library. Input from stdin, output to stdout. - Focused on Aggregates threat intelligence data from various open-source feeds and web pages (e.g., vulnerability databases, security blogs, Twitter feeds) into a unified format for analysis and alerting. Allows for filtering and correlation of threat indicators. Focus is on collecting and structuring existing intelligence, not generating new intelligence.

## Install
`git clone https://github.com/ShadowGuard-AI/tia-indicatortypeconverter`

## Usage
`python main.py -t <conversion> -i <input>`

Failed conversions, a refused oversize CIDR block, and empty input all exit non-zero with the reason on stderr. `url_to_domain` returns the host only, so URL credentials and ports never appear in the output. In `deduplicate_ips`, malformed entries are dropped one by one with a count reported, and the valid entries are still printed.

DNS note: conversions are local and need no network access. The one exception is opt-in: passing `--resolve` with `domain_to_url` also checks that the domain resolves, which sends that domain to your system DNS resolver. The check never changes the converted URL, and it is off by default.

## Parameters
- `-h`: Show help message and exit
- `-t`: The type of conversion to perform.
- `-s`: The URL scheme for domain_to_url (default: http). It must match the RFC scheme shape: a letter followed by letters, digits, `+`, `-`, or `.`
- `-i`: The input string. If not provided, reads from stdin.
- `--resolve`: For domain_to_url only, also check DNS resolution (see the DNS note above). Off by default.

## License
Copyright (c) ShadowGuard-AI
