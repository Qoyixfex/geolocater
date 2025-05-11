import requests
import socket
import json
import webbrowser
from ipwhois import IPWhois
import folium
import maxminddb
from concurrent.futures import ThreadPoolExecutor
import time

class GeoLocator:
    def __init__(self):
        # Initialize with free API keys (you may need to get your own)
        self.apis = {
            'ipapi': 'https://ipapi.co/{ip}/json/',
            'ipinfo': 'https://ipinfo.io/{ip}/json?token=YOUR_TOKEN_HERE',  # Replace with your token
            'ipgeolocation': 'https://api.ipgeolocation.io/ipgeo?apiKey=4f9271cb9ac63c&ip={ip}'  # Replace with your key
        }
        
        # Try to load local MaxMind DB (you need to download this separately)
        try:
            self.reader = maxminddb.open_database('GeoLite2-City.mmdb')
        except:
            self.reader = None
            print("MaxMind DB not found. Some features will be limited.")
    
    def get_ip_info(self, ip_address=None):
        """Get comprehensive information about an IP address"""
        if not ip_address:
            ip_address = self.get_public_ip()
        
        results = {}
        
        # Use ThreadPool to query all APIs simultaneously
        with ThreadPoolExecutor() as executor:
            futures = {
                'ipapi': executor.submit(self.query_api, 'ipapi', ip_address),
                'ipinfo': executor.submit(self.query_api, 'ipinfo', ip_address),
                'ipgeolocation': executor.submit(self.query_api, 'ipgeolocation', ip_address),
                'whois': executor.submit(self.get_whois_info, ip_address),
                'maxmind': executor.submit(self.get_maxmind_info, ip_address),
                'dns': executor.submit(self.get_dns_info, ip_address),
                'hostname': executor.submit(self.get_hostname, ip_address)
            }
            
            for name, future in futures.items():
                try:
                    results[name] = future.result()
                except Exception as e:
                    results[name] = f"Error getting {name}: {str(e)}"
        
        return results
    
    def query_api(self, api_name, ip_address):
        """Query a specific API"""
        if api_name not in self.apis:
            return f"API {api_name} not configured"
        
        url = self.apis[api_name].format(ip=ip_address)
        response = requests.get(url, timeout=10)
        return response.json()
    
    def get_public_ip(self):
        """Get the public IP address of the current machine"""
        try:
            return requests.get('https://api.ipify.org?format=json').json()['ip']
        except:
            return socket.gethostbyname(socket.gethostname())
    
    def get_whois_info(self, ip_address):
        """Get WHOIS information for an IP"""
        obj = IPWhois(ip_address)
        return obj.lookup_rdap()
    
    def get_maxmind_info(self, ip_address):
        """Get geolocation info from local MaxMind DB"""
        if not self.reader:
            return "MaxMind DB not available"
        return self.reader.get(ip_address)
    
    def get_dns_info(self, ip_address):
        """Get DNS information for an IP"""
        try:
            return socket.gethostbyaddr(ip_address)
        except:
            return "DNS lookup failed"
    
    def get_hostname(self, ip_address):
        """Get hostname for an IP"""
        try:
            return socket.getfqdn(ip_address)
        except:
            return "Hostname lookup failed"
    
    def visualize_on_map(self, ip_address=None):
        """Create a map visualization of the IP location"""
        info = self.get_ip_info(ip_address)
        
        # Try to get coordinates from various sources
        lat, lon = None, None
        for source in ['ipapi', 'ipinfo', 'ipgeolocation', 'maxmind']:
            if source in info and isinstance(info[source], dict):
                if 'latitude' in info[source] and 'longitude' in info[source]:
                    lat = info[source]['latitude']
                    lon = info[source]['longitude']
                    break
                elif 'loc' in info[source]:
                    loc = info[source]['loc'].split(',')
                    if len(loc) == 2:
                        lat, lon = loc
                        break
        
        if not lat or not lon:
            print("Could not determine location coordinates")
            return
        
        # Create map
        m = folium.Map(location=[float(lat), float(lon)], zoom_start=10)
        folium.Marker(
            [float(lat), float(lon)],
            popup=f"IP: {ip_address}",
            tooltip="Click for details"
        ).add_to(m)
        
        # Save and open map
        filename = f"ip_location_{ip_address}.html"
        m.save(filename)
        webbrowser.open(filename)
    
    def trace_route(self, target):
        """Perform a traceroute (Linux/Mac only)"""
        import subprocess
        try:
            result = subprocess.run(['traceroute', target], capture_output=True, text=True)
            return result.stdout
        except:
            return "Traceroute failed or not supported on this system"
    
    def bulk_lookup(self, ip_list):
        """Perform bulk lookup of multiple IPs"""
        results = {}
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_ip = {executor.submit(self.get_ip_info, ip): ip for ip in ip_list}
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    results[ip] = future.result()
                except Exception as e:
                    results[ip] = f"Error: {str(e)}"
        return results

def main():
    locator = GeoLocator()
    print("Advanced Geolocation Tool")
    print("1. Lookup IP information")
    print("2. Visualize IP on map")
    print("3. Traceroute to target")
    print("4. Bulk IP lookup")
    
    choice = input("Select an option (1-4): ")
    
    if choice == '1':
        ip = input("Enter IP address (leave blank for your IP): ")
        result = locator.get_ip_info(ip if ip else None)
        print(json.dumps(result, indent=2))
    elif choice == '2':
        ip = input("Enter IP address (leave blank for your IP): ")
        locator.visualize_on_map(ip if ip else None)
    elif choice == '3':
        target = input("Enter target host or IP: ")
        print(locator.trace_route(target))
    elif choice == '4':
        ips = input("Enter IPs separated by commas: ").split(',')
        results = locator.bulk_lookup([ip.strip() for ip in ips])
        for ip, data in results.items():
            print(f"\nResults for {ip}:")
            print(json.dumps(data, indent=2))
    else:
        print("Invalid choice")

if __name__ == "__main__":
    main()
