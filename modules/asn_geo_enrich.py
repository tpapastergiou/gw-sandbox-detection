import argparse
import json

@dataclass
class GeoResult:
    city: Optional[str]
    country: Optional[str]
    country_iso: Optional[str]
    latitude: Optional[float]
    longitude: Optional[float]

@dataclass
class ASNResult:
    asn: Optional[int]
    asn_org: Optional[str]
    network: Optional[str]  # CIDR block MaxMind matched (e.g., "8.8.8.0/24")


def lookup_asn(ip: str, mmdb_path: str) -> ASNResult:
    with geoip2.database.Reader(mmdb_path) as reader:
        try:
            r = reader.asn(ip)
            return ASNResult(
                asn=r.autonomous_system_number,
                asn_org=r.autonomous_system_organization,
                network=str(r.network) if r.network else None,
            )
        except (geoip2.errors.AddressNotFoundError, ValueError):
            return ASNResult(asn=None, asn_org=None, network=None)

def geolocate_ip(ip: str, mmdb_path: str) -> GeoResult:
    with geoip2.database.Reader(mmdb_path) as reader:
        try:
            r = reader.city(ip)
            return GeoResult(
                city=r.city.name,
                country=r.country.name,
                country_iso=r.country.iso_code,
                latitude=r.location.latitude,
                longitude=r.location.longitude,
            )
        except (geoip2.errors.AddressNotFoundError, ValueError):
            # AddressNotFoundError: IP not in DB; ValueError: invalid IP string
            return GeoResult(city=None, country=None, country_iso=None, latitude=None, longitude=None)


def process_file(input_path: str, output_path: str) -> None:
    # Stream JSONL input line-by-line and write JSONL line-by-line (no full read into memory).
    #create output directory if it doesn't exist
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(input_path, "r", encoding="utf-8") as fin, open(output_path, "w", encoding="utf-8") as fout:
        for lineno, line in enumerate(fin, start=1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"Skipping line {lineno} in {input_path} due to JSON decode error: {e}")
                continue

            ip = record.get("ip")

            # Here you would enrich the record with Maxmind data using the provided databases.
            # For example:
            # record["geo"] = geolocate_ip(record["ip"], maxmind_db_city)
            # record["asn"] = get_asn(record["ip"], maxmind_db_asn)

            fout.write(json.dumps(record, ensure_ascii=False) + "\n")





if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Geolocate/enrich IPs with Maxmind")
    parser.add_argument("input_file", help="Path to input file")
    parser.add_argument("output_file", help="Path to output file for JSONL results")
    parser.add_argument("--maxmind-db-city", help="Path to GeoLite2-City.mmdb", required=True)
    parser.add_argument("--maxmind-db-asn", help="Path to GeoLite2-ASN.mmdb", required=True)
    args = parser.parse_args()
    print(f"Starting {args.input_file}")
    process_file(args.input_file, args.output_file)
    print(f"Finished {args.input_file}")