
import base64
import json
import requests
import re
import socket
import os
import time
import ipaddress

try:
    import maxminddb
except ImportError:
    maxminddb = None


# -----------------------------
# Geolocation configuration
# -----------------------------

DATABASE_FILE = "databases/dbip-country-lite.mmdb"

REQUEST_DELAY = 1.5

API_SERVICES = [
    "ipwho.is",
    "ipapi.co",
    "ip-api.com",
    "ip.guide",
    "ip.sb"
]

session = requests.Session()

next_request_time = 0
api_index = 0

# DNS and country caches
dns_cache = {}
country_cache = {}


# -----------------------------
# Rate limiting
# -----------------------------

def wait_rate():
    global next_request_time

    now = time.monotonic()

    if now < next_request_time:
        time.sleep(next_request_time - now)

    next_request_time = time.monotonic() + REQUEST_DELAY


# -----------------------------
# Private IP filtering
# -----------------------------

def is_private_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)

        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_reserved
            or addr.is_link_local
            or addr.is_multicast
        )

    except ValueError:
        return True


# -----------------------------
# DNS resolution with caching
# -----------------------------

def resolve_hostname(host):
    if host in dns_cache:
        return dns_cache[host]

    try:
        # Accept an IP address directly without DNS resolution
        try:
            ip = str(ipaddress.ip_address(host))
        except ValueError:
            ip = socket.gethostbyname(host)

        dns_cache[host] = ip
        return ip

    except (socket.gaierror, UnicodeError, OSError) as e:
        print(f"DNS resolution failed: {host} | {e}")
        return None


# -----------------------------
# Local database lookup
# -----------------------------

def lookup_local_database(ip):
    if maxminddb is None:
        return None

    reader = None

    try:
        reader = maxminddb.open_database(DATABASE_FILE)

        result = reader.get(ip)

        if not result:
            return None

        country = (
            result
            .get("country", {})
            .get("iso_code")
        )

        if country and re.fullmatch(r"[A-Za-z]{2}", country):
            return country.upper()

    except Exception as e:
        print(f"Local database lookup failed for {ip}: {e}")

    finally:
        if reader is not None:
            try:
                reader.close()
            except Exception:
                pass

    return None


# -----------------------------
# API fallback lookup
# -----------------------------

def api_lookup(ip):
    global api_index

    # Try all five providers, rotating the starting provider
    for _ in range(len(API_SERVICES)):

        service = API_SERVICES[api_index]

        api_index = (api_index + 1) % len(API_SERVICES)

        try:
            wait_rate()

            print(f"Querying API: {service} -> {ip}")

            if service == "ipwho.is":

                r = session.get(
                    f"https://ipwho.is/{ip}",
                    timeout=10
                )

                r.raise_for_status()
                data = r.json()

                country = data.get("country_code")


            elif service == "ipapi.co":

                r = session.get(
                    f"https://ipapi.co/{ip}/json/",
                    timeout=10
                )

                r.raise_for_status()
                data = r.json()

                country = data.get("country")


            elif service == "ip-api.com":

                r = session.get(
                    f"http://ip-api.com/json/{ip}",
                    timeout=10
                )

                r.raise_for_status()
                data = r.json()

                country = data.get("countryCode")


            elif service == "ip.guide":

                r = session.get(
                    f"https://ip.guide/{ip}",
                    timeout=10
                )

                r.raise_for_status()
                data = r.json()

                country = (
                    data
                    .get("location", {})
                    .get("country_code")
                )


            elif service == "ip.sb":

                r = session.get(
                    f"https://api.ip.sb/geoip/{ip}",
                    timeout=10
                )

                r.raise_for_status()
                data = r.json()

                country = data.get("country_code")


            else:
                country = None


            if (
                isinstance(country, str)
                and re.fullmatch(r"[A-Za-z]{2}", country.strip())
            ):
                return country.strip().upper()

            raise Exception("No valid country code returned")


        except Exception as e:

            print(f"API failed {service} {ip}: {e}")

            # Continue to the next provider
            continue

    return None


# -----------------------------
# Main country resolver
# -----------------------------

def get_country_code(address):

    # Resolve hostname or normalize IP address
    ip = resolve_hostname(address)

    if not ip:
        return None

    # Reject private and non-public IP addresses
    if is_private_ip(ip):
        print(f"Skipping private/reserved IP: {ip}")
        return None

    # Check country cache
    if ip in country_cache:
        return country_cache[ip]

    # First: Local database lookup
    print(f"Querying local database: {ip}")

    country = lookup_local_database(ip)

    if country:
        country_cache[ip] = country
        return country

    # Fallback: Five online API providers
    print(f"Local database failed, using APIs: {ip}")

    country = api_lookup(ip)

    if country:
        country_cache[ip] = country

    return country


# -----------------------------
# Country flag conversion
# -----------------------------

def country_code_to_emoji(country_code):
    # Convert country code to Unicode regional indicator symbols
    return ''.join(
        chr(ord(letter) + 127397)
        for letter in country_code.upper()
    )


# Counter for all proxies
proxy_counter = 0


def process_vmess(proxy):
    global proxy_counter

    base64_str = proxy.split('://')[1]

    missing_padding = len(base64_str) % 4

    if missing_padding:
        base64_str += '=' * (4 - missing_padding)

    try:
        decoded_str = base64.b64decode(base64_str).decode('utf-8')

        proxy_json = json.loads(decoded_str)

        ip_address = proxy_json['add']

        country_code = get_country_code(ip_address)

        if country_code is None:
            return None

        flag_emoji = country_code_to_emoji(country_code)

        proxy_counter += 1

        remarks = (
            flag_emoji
            + country_code
            + '_'
            + str(proxy_counter)
            + '_'
            + '@Surfboardv2ray'
        )

        proxy_json['ps'] = remarks

        encoded_str = base64.b64encode(
            json.dumps(proxy_json).encode('utf-8')
        ).decode('utf-8')

        processed_proxy = 'vmess://' + encoded_str

        return processed_proxy

    except Exception as e:
        print("Error processing vmess proxy: ", e)
        return None


def process_vless_like(proxy):
    global proxy_counter

    try:
        ip_address = proxy.split('@')[1].split(':')[0]

    except Exception:
        return None

    country_code = get_country_code(ip_address)

    if country_code is None:
        return None

    flag_emoji = country_code_to_emoji(country_code)

    proxy_counter += 1

    remarks = (
        flag_emoji
        + country_code
        + '_'
        + str(proxy_counter)
        + '_'
        + '@Surfboardv2ray'
    )

    processed_proxy = proxy.split('#')[0] + '#' + remarks

    return processed_proxy


# -----------------------------
# Process the proxies
# -----------------------------

os.makedirs("sort", exist_ok=True)

with open('tg/config.txt', 'r') as f, open('sort/sort.txt', 'w') as out_f:

    proxies = f.readlines()

    for proxy in proxies:

        proxy = proxy.strip()

        processed_proxy = None

        if proxy.startswith('vmess://'):
            processed_proxy = process_vmess(proxy)

        elif (
            proxy.startswith('vless://')
            or proxy.startswith('trojan://')
            or proxy.startswith('ss://')
        ):
            processed_proxy = process_vless_like(proxy)

        if processed_proxy is not None:
            out_f.write(processed_proxy + '\n')


# -----------------------------
# Separate configurations by country
# -----------------------------

with open('sort/sort.txt', 'r') as in_f:

    proxies = in_f.readlines()

    with open('sort/IR.txt', 'w') as ir_f, open('sort/US.txt', 'w') as us_f:

        for proxy in proxies:

            if 'IR_' in proxy:
                ir_f.write(proxy)

            elif 'US_' in proxy:
                us_f.write(proxy)
