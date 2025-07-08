import argparse
import sys
import logging
from netaddr import IPAddress, IPNetwork, AddrFormatError, IPSet
import re
import socket
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def ip_to_cidr(ip_address):
    """
    Converts a single IP address to a CIDR /32 notation.

    Args:
        ip_address (str): The IP address to convert.

    Returns:
        str: The CIDR notation of the IP address (e.g., "192.168.1.1/32") or None if an error occurs.
    """
    try:
        IPAddress(ip_address)  # Validate the IP address
        return f"{ip_address}/32"
    except AddrFormatError:
        logging.error(f"Invalid IP address: {ip_address}")
        return None

def domain_to_url(domain, scheme="http"):
    """
    Converts a domain name to a URL (defaulting to HTTP scheme).

    Args:
        domain (str): The domain name to convert.
        scheme (str): The URL scheme (default: "http").

    Returns:
        str: The URL of the domain (e.g., "http://example.com") or None if an error occurs.
    """
    try:
        # Basic validation: Check if the domain contains only valid characters
        if not re.match(r"^[a-zA-Z0-9.-]+$", domain):
            raise ValueError(f"Invalid characters in domain: {domain}")
        
        # Check if the domain resolves to an IP address.  This is a basic liveness check.
        try:
            socket.gethostbyname(domain)  # Resolve the domain
        except socket.gaierror:
            logging.warning(f"Domain {domain} does not resolve.")
            # Still attempt to create the URL, but warn the user
            pass
        
        return f"{scheme}://{domain}"
    except ValueError as e:
        logging.error(f"Invalid domain: {domain} - {e}")
        return None
    except Exception as e:
        logging.error(f"Error converting domain to URL: {domain} - {e}")
        return None

def url_to_domain(url):
    """
    Extracts the domain name from a URL.

    Args:
        url (str): The URL to extract the domain from.

    Returns:
        str: The domain name of the URL (e.g., "example.com") or None if an error occurs.
    """
    try:
        parsed_url = urlparse(url)
        if not parsed_url.netloc:
            raise ValueError(f"Invalid URL: {url}")

        return parsed_url.netloc
    except ValueError as e:
        logging.error(f"Invalid URL: {url} - {e}")
        return None
    except Exception as e:
        logging.error(f"Error extracting domain from URL: {url} - {e}")
        return None
    
def cidr_to_ips(cidr):
    """
    Expands a CIDR notation to a list of IP addresses.  Be mindful of large CIDR blocks.

    Args:
        cidr (str): The CIDR notation to expand (e.g., "192.168.1.0/24").

    Returns:
        list: A list of IP addresses in the CIDR block, or None if an error occurs.
    """
    try:
        network = IPNetwork(cidr)
        # Limit the size of the network to prevent memory exhaustion
        if network.size > 256: # Limiting to /24
            logging.warning(f"CIDR block {cidr} is larger than /24. Consider using a more specific block.")
            return None
        return [str(ip) for ip in network]
    except AddrFormatError:
        logging.error(f"Invalid CIDR notation: {cidr}")
        return None
    except Exception as e:
        logging.error(f"Error expanding CIDR: {cidr} - {e}")
        return None
    

def deduplicate_ips(ip_list):
    """
    Deduplicates a list of IP addresses using an IPSet.

    Args:
        ip_list (list): A list of IP addresses.

    Returns:
        list: A deduplicated list of IP addresses.
    """
    try:
        ip_set = IPSet(ip_list)
        return sorted([str(ip) for ip in ip_set])
    except AddrFormatError as e:
        logging.error(f"Invalid IP address found: {e}")
        return []
    except Exception as e:
        logging.error(f"Error deduplicating IPs: {e}")
        return []


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description="Convert indicators between different formats.")
    parser.add_argument("-t", "--type", choices=["ip_to_cidr", "domain_to_url", "url_to_domain", "cidr_to_ips", "deduplicate_ips"],
                        required=True, help="The type of conversion to perform.")
    parser.add_argument("-s", "--scheme", default="http", help="The URL scheme (default: http).  Used for domain_to_url.")
    parser.add_argument("-i", "--input", help="The input string. If not provided, reads from stdin.")
    return parser

def main():
    """
    Main function to process input and perform the specified conversion.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Determine input source
    if args.input:
        input_data = args.input
    else:
        input_data = sys.stdin.read().strip()

    if not input_data:
        logging.warning("No input data provided.")
        return

    try:
        if args.type == "ip_to_cidr":
            result = ip_to_cidr(input_data)
            if result:
                print(result)
        elif args.type == "domain_to_url":
            result = domain_to_url(input_data, scheme=args.scheme)
            if result:
                print(result)
        elif args.type == "url_to_domain":
            result = url_to_domain(input_data)
            if result:
                print(result)
        elif args.type == "cidr_to_ips":
            result = cidr_to_ips(input_data)
            if result:
                for ip in result:
                    print(ip)
        elif args.type == "deduplicate_ips":
            # Deduplicate IPs expects a list of IPs.  Split the input data on newlines.
            ip_list = input_data.splitlines()
            result = deduplicate_ips(ip_list)
            if result:
                for ip in result:
                    print(ip)
        else:
            logging.error(f"Invalid conversion type: {args.type}")
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()