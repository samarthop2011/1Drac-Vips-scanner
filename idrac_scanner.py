import requests
import ipaddress
from typing import List, Dict

# ==================================================================
# ⚙️ CONFIGURATION
# ==================================================================

# IMPORTANT: Replace this with your actual Discord Webhook URL
DISCORD_WEBHOOK_URL = "YOUR_DISCORD_WEBHOOK_URL_HERE"

# Ports commonly used by iDRAC/iLO/BMC interfaces
TARGET_PORTS = [80, 443, 3389] 

# Keywords to look for in the HTTP response (indicating an iDRAC/Server Interface)
IDRAC_KEYWORDS = [
    "idrac", 
    "dell.com", 
    "hpe.com", 
    "bmc", 
    "oracle.com/idrac", 
    "servercenter"
]

# ==================================================================
# 🚀 CORE SCANNING FUNCTIONS
# ==================================================================

def is_valid_ip(ip_string: str) -> bool:
    """Checks if the string provided is a valid IPv4 address."""
    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False

def check_ip_idrac_vulnerability(ip_address: str) -> Dict:
    """
    Pings the IP and checks specified ports for iDRAC indicators.
    Returns a dictionary detailing the scan results.
    """
    print(f"   [SCANNING] -> {ip_address}...")
    
    result = {
        "ip": ip_address,
        "vulnerable": False,
        "is_idrac": False,
        "ports_open": []
    }
    
    # 1. Simple Ping Check (or basic connectivity check)
    is_reachable = False
    try:
        # Use a short timeout to avoid blocking the script
        requests.get(f"http://{ip_address}", timeout=3)
        is_reachable = True
    except requests.exceptions.RequestException:
        # If the basic connection fails, it might still be reachable on other ports
        pass

    if not is_reachable:
        result["status"] = "Not Reachable (Ping failed)"
        return result

    # 2. Detailed Port Check
    for port in TARGET_PORTS:
        port_url = f"http://{ip_address}:{port}"
        try:
            response = requests.get(port_url, timeout=2)
            result["ports_open"].append(port)

            # 3. Keyword Analysis (Checking the content)
            content = response.text.lower()
            for keyword in IDRAC_KEYWORDS:
                if keyword in content:
                    result["is_idrac"] = True
                    result["vulnerable"] = True # Assume if it's iDRAC, it's a target
                    result["status"] = "iDRAC Detected & Vulnerable"
                    # Once a keyword matches, we can break the keyword loop
                    break
            
            if result["is_idrac"] and result["vulnerable"]:
                # Optimization: If we found iDRAC, we don't need to check other ports for keywords, 
                # but we continue to list all open ports.
                pass 

        except requests.exceptions.RequestException:
            # Port is closed or timed out
            pass
    
    # Final status update if not explicitly set
    if result["is_idrac"] and not result["vulnerable"]:
        # Found iDRAC structure, but no keyword match (maybe a custom implementation)
        result["status"] = "iDRAC Detected (Keyword Match Pending)"
    elif result["is_reachable"] and not result["is_idrac"]:
        # Reached the IP, but no iDRAC signature found
        result["status"] = "Reachable (Not iDRAC/Unknown)"
    elif result["is_reachable"] and not result["ports_open"]:
        # Reached the IP, but no common ports opened (rare)
        result["status"] = "Reachable (No common ports open)"

    return result

# ==================================================================
# 💬 DISCORD WEBHOOK FUNCTION
# ==================================================================

def send_discord_webhook(results: List[Dict]):
    """Formats the results and sends them to the configured Discord Webhook."""
    
    vulnerable_ips = [r for r in results if r["vulnerable"]]
    total_scanned = len(results)
    
    if total_scanned == 0:
        print("\n❌ No IPs provided to scan.")
        return

    # --- Constructing the Embed Message ---
    embed = {
        "title": "📡 iDRAC Vulnerability Scan Report",
        "description": f"A scan of **{total_scanned}** IP addresses has been completed.",
        "color": 3066993,  # A bright blue color
        "fields": [],
        "footer": {
            "text": "System Scanner v1.0"
        }
    }
    
    # Summary Field
    vulnerable_summary = f"✅ **{len(vulnerable_ips)}** IP(s) Detected as Vulnerable iDRAC/BMC"
    if len(vulnerable_ips) == 0:
        vulnerable_summary = "❌ **0** IP(s) Detected as Vulnerable iDRAC/BMC"
        
    embed["fields"].append({
        "name": "✨ Summary",
        "value": vulnerable_summary,
        "inline": False
    })

    # Detailed IP List
    details_field_value = ""
    for res in results:
        ip_status = f"**{res['ip']}** ({res['status']})"
        if res['ports_open']:
            ports_str = ", ".join(map(str, res['ports_open']))
            ip_status += f" 🚪 Ports: `{ports_str}`"
        else:
            ip_status += " 🚪 Ports: None"
        
        if res['vulnerable']:
            # Highlight vulnerable IPs in bold and green
            details_field_value += f"🟢 {ip_status}\n"
        elif res['is_idrac']:
             # Highlight non-vulnerable but detected iDRAC
            details_field_value += f"🟡 {ip_status} (Detected iDRAC)\n"
        else:
            # Standard reachable/unidentified IP
            details_field_value += f"⚪ {ip_status}\n"

    embed["fields"].append({
        "name": "📋 Detailed Results",
        "value": f"```\n{details_field_value.strip()}\n```",
        "inline": False
    })

    # --- Sending the Request ---
    if DISCORD_WEBHOOK_URL == "YOUR_DISCORD_WEBHOOK_URL_HERE":
        print("\n" + "="*60)
        print("🚨 WARNING: DISCORD WEBHOOK URL NOT SET!")
        print("Please replace 'YOUR_DISCORD_WEBHOOK_URL_HERE' in the code.")
        print("The results were printed locally instead.")
        print("="*60)
        print("\n--- LOCAL SCAN RESULTS ---")
        print(f"TOTAL SCANNED: {total_scanned}")
        print(f"VULNERABLE COUNT: {len(vulnerable_ips)}")
        print("="*60)
        for res in results:
            print(f"[{'VULN' if res['vulnerable'] else 'OK'}] {res['ip']} - Status: {res['status']} | Ports: {res['ports_open']}")
        return

    try:
        response = requests.post(
            DISCORD_WEBHOOK_URL,
            json=embed,
            headers={"Content-Type": "application/json"}
        )
        response.raise_for_status() # Raises an HTTPError for bad responses (4xx or 5xx)
        print("\n✅ SUCCESS: Scan results successfully posted to Discord Webhook!")
    except requests.exceptions.RequestException as e:
        print(f"\n❌ ERROR: Failed to post results to Discord Webhook.")
        print(f"Details: {e}")

# ==================================================================
# 🧠 MAIN EXECUTION BLOCK
# ==================================================================

if __name__ == "__main__":
    print("=======================================")
    print("  🚀 iDRAC Vulnerability IP Scanner 🚀")
    print("=======================================")
    
    # Get input from the user
    ip_batch_input = input("Paste a list of IP addresses, separated by commas or spaces:\n> ")
    
    # Process the input into a clean list
    # Splits by comma OR space and filters out any empty strings
    raw_ips = [ip.strip() for ip in ip_batch_input.replace(',', ' ').split()]
    
    # Validate and filter the IPs
    ips_to_scan = [ip for ip in raw_ips if is_valid_ip(ip)]
    invalid_ips = [ip for ip in raw_ips if not is_valid_ip(ip)]

    if not ips_to_scan:
        print("\n🚨 No valid IP addresses were detected in the input.")
        if invalid_ips:
            print(f"Invalid IPs provided: {', '.join(invalid_ips)}")
        exit()

    print(f"\n--- Starting Scan for {len(ips_to_scan)} Valid IPs ---")
    
    scan_results = []
    
    # Run the scanner for every IP
    for ip in ips_to_scan:
        result = check_ip_idrac_vulnerability(ip)
        scan_results.append(result)

    # Send the results to Discord
    send_discord_webhook(scan_results)
