import regex    
from tldextract import extract
import ssl
import socket
from bs4 import BeautifulSoup
import urllib.request
import whois
import datetime
import requests
import favicon
import re
from googlesearch import search

#1. Checking if URL contains any IP address. Returns -1 if contains else returns 1
def having_IPhaving_IP_Address(url):
    match = regex.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # IPv6
    return -1 if match else 1

# 2.Checking for the URL length. Returns 1 (Legitimate) if the URL length is less than 54 characters
def URLURL_Length(url):
    length = len(url)
    if length <= 75:
        return 1 if length < 54 else 0
    return -1

#3. Checking with the shortening URLs.
def Shortining_Service(url):
    match = regex.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                         'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                         'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                         'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                         'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                         'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                         'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net', url)
    return -1 if match else 1

#4.Checking for @ symbol. Returns 1 if no @ symbol found. Else returns -1.
def having_At_Symbol(url):
    return 1 if '@' not in url else -1 

# 5.Checking for Double Slash redirections. Returns -1 if // found. Else returns 1
def double_slash_redirecting(url):
    return -1 if '//' in url else 1

#6. Checking for - in Domain. Returns -1 if '-' is found else returns 1.
def Prefix_Suffix(url):
    domain_info = extract(url)
    return -1 if '-' in domain_info.domain else 1

# 7.Checking the Subdomain. Returns 1 if the subDomain contains less than 1 '.'
# Returns 0 if the subDomain contains less than 2 '.'
# Returns -1 if the subDomain contains more than 2 '.'
def having_Sub_Domain(url):
    domain_info = extract(url)
    subdomain = domain_info.subdomain
    return 1 if subdomain.count('.') <= 1 else 0 if subdomain.count('.') <= 2 else -1

# 8.Checking the SSL. Returns 1 if it returns the response code and -1 if exceptions are thrown.
def SSLfinal_State(url):
    try:
        response = requests.get(url)
        return 1
    except Exception as e:
        return -1

#9.domains expires on ≤ 1 year returns -1, otherwise returns 1
def Domain_registeration_length(url):
    try:
        domain = whois.whois(url)
        exp = domain.expiration_date[0]
        up = domain.updated_date[0]
        domainlen = (exp - up).days
        return -1 if domainlen <= 365 else 1
    except:
        return -1

# 10.Checking the Favicon. Returns 1 if the domain of the favicon image and the URL domain match else returns -1.
def Favicon(url):
    domain_info = extract(url)
    try:
        icons = favicon.get(url)
        icon = icons[0]
        favicon_domain_info = extract(icon.url)
        return 1 if favicon_domain_info.domain == domain_info.domain else -1
    except:
        return -1

#11.Checking the Port of the URL. Returns 1 if the port is available else returns -1.
def port(url):
    try:
        a_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        location = (url[7:], 80)
        result_of_check = a_socket.connect_ex(location)
        a_socket.close()
        return 1 if result_of_check == 0 else -1
    except:
        return -1

#12. HTTPS token in part of domain of URL returns -1, otherwise returns 1
def HTTPS_token(url):
    match = re.search('https://|http://', url)
    if match.start(0) == 0:
        url = url[match.end(0):]
    match = re.search('http|https', url)
    return -1 if match else 1

# 13.% of request URL<22% returns 1, otherwise returns -1
def Request_URL(url):
    try:
        domain_info = extract(url)
        websiteDomain = domain_info.domain
        opener = urllib.request.urlopen(url).read()
        soup = BeautifulSoup(opener, 'lxml')
        imgs = soup.findAll('img', src=True)
        total = len(imgs)
        linked_to_same = 0
        avg = 0
        for image in imgs:
            image_domain_info = extract(image['src'])
            imageDomain = image_domain_info.domain
            if websiteDomain == imageDomain or imageDomain == '':
                linked_to_same += 1
        vids = soup.findAll('video', src=True)
        total += len(vids)
        for video in vids:
            video_domain_info = extract(video['src'])
            vidDomain = video_domain_info.domain
            if websiteDomain == vidDomain or vidDomain == '':
                linked_to_same += 1
        linked_outside = total - linked_to_same
        if total != 0:
            avg = linked_outside / total
        return 1 if avg < 0.22 else -1
    except:
        return -1

# 14.:% of URL of anchor<31% returns 1, % of URL of anchor ≥ 31% and ≤ 67% returns 0, otherwise returns -1
def URL_of_Anchor(url):
    try:
        domain_info = extract(url)
        websiteDomain = domain_info.domain
        opener = urllib.request.urlopen(url).read()
        soup = BeautifulSoup(opener, 'lxml')
        anchors = soup.findAll('a', href=True)
        total = len(anchors)
        linked_to_same = 0
        avg = 0
        for anchor in anchors:
            anchor_domain_info = extract(anchor['href'])
            anchorDomain = anchor_domain_info.domain
            if websiteDomain == anchorDomain or anchorDomain == '':
                linked_to_same += 1
        linked_outside = total - linked_to_same
        if total != 0:
            avg = linked_outside / total
        return 1 if avg < 0.31 else 0 if 0.31 <= avg <= 0.67 else -1
    except:
        return 0

#15. :% of links in <meta>, <script>and<link>tags < 25% returns 1, % of links in <meta>,
# <script> and <link> tags ≥ 25% and ≤ 81% returns 0, otherwise returns -1
def Links_in_tags(url):
    try:
        opener = urllib.request.urlopen(url).read()
        soup = BeautifulSoup(opener, 'lxml')
        no_of_meta = 0
        no_of_link = 0
        no_of_script = 0
        anchors = 0
        avg = 0
        for meta in soup.find_all('meta'):
            no_of_meta += 1
        for link in soup.find_all('link'):
            no_of_link += 1
        for script in soup.find_all('script'):
                        no_of_script += 1
        for anchor in soup.find_all('a'):
            anchors += 1
        total = no_of_meta + no_of_link + no_of_script + anchors
        tags = no_of_meta + no_of_link + no_of_script
        if total != 0:
            avg = tags / total
        return -1 if avg < 0.25 else 0 if 0.25 <= avg <= 0.81 else 1
    except:
        return 0

# 16.Server Form Handling
# SFH is "about: blank" or empty → phishing, SFH refers to a different domain → suspicious, otherwise → legitimate
def SFH(url):
    # ongoing
    return -1

# 17.:using "mail()" or "mailto:" returning -1, otherwise returns 1
def Submitting_to_email(url):
    try:
        opener = urllib.request.urlopen(url).read()
        soup = BeautifulSoup(opener, 'lxml')
        if soup.find('mailto:', 'mail():'):
            return -1
        else:
            return 1
    except:
        return -1

#18.Host name is not in URL returns -1, otherwise returns 1
def Abnormal_URL(url):
    domain_info = extract(url)
    try:
        domain = whois.whois(url)
        hostname = domain.domain_name[0].lower()
        match = re.search(hostname, url)
        return 1 if match else -1
    except:
        return -1

# 19.number of redirect page ≤ 1 returns 1, otherwise returns 0
def Redirect(url):
    try:
        request = requests.get(url)
        a = request.history
        return 1 if len(a) <= 1 else 0
    except:
        return 0

#20. onMouseOver changes status bar returns -1, otherwise returns 1
def on_mouseover(url):
    try:
        opener = urllib.request.urlopen(url).read()
        soup = BeautifulSoup
        if soup.find(onmouseover=True):
            return -1
        else:
            return 1
    except:
        return -1

# 21.RightClick disables returns -1, otherwise returns 1
def RightClick(url):
    try:
        opener = urllib.request.urlopen(url).read()
        soup = BeautifulSoup(opener, 'lxml')
        if soup.find(oncontextmenu="function disableSelection"):
            return -1
        else:
            return 1
    except:
        return -1
#22.popupwindow
def popUpWidnow(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        popup_windows = soup.find_all('input', {'type': 'text'})
        if popup_windows:
            return 1  # phishing
        else:
            return 0  # legitimate
    except Exception as e:
        print(f"Error in popUpWidnow: {e}")
        return 0  # legitimate by default

# 23.IFrame Redirection returns -1, otherwise returns 1
def iFrame(url):
    try:
        opener = urllib.request.urlopen(url).read()
        soup = BeautifulSoup(opener, 'lxml')
        if soup.find(iframe=True):
            return -1
        else:
            return 1
    except:
        return -1

#24. Age of Domain returns -1 if age is less than 6 months, otherwise returns 1
def Domain_Age(url):
    try:
        domain = whois.whois(url)
        creation_date = domain.creation_date[0]
        end_date = datetime.datetime.now()
        age = (end_date - creation_date).days
        return -1 if age < 180 else 1
    except:
        return -1

#25. DNS Record availability returns -1 if DNS record is not available, otherwise returns 1
def DNS_Record(url):
    try:
        domain = whois.whois(url)
        return 1 if domain else -1
    except:
        return -1

#26. Web Traffic returns -1 if web traffic is less than 1000, otherwise returns 1
def Web_Traffic(url):
    try:
        search_results = list(search(url, num_results=10))
        return -1 if len(search_results) < 1000 else 1
    except:
        return -1

#27. Page Rank returns -1 if page rank is less than 0.2, otherwise returns 1
def Page_Rank(url):
    try:
        rank = 0  # implement page rank algorithm
        return -1 if rank < 0.2 else 1
    except:
        return -1

#28. Google Index returns -1 if google index is less than 100, otherwise returns 1
def Google_Index(url):
    try:
        search_results = list(search(url, num_results=10))
        return -1 if len(search_results) < 100 else 1
    except:
        return -1

#29. Links Pointing to Page returns -1 if links pointing to page is less than 2, otherwise returns 1
def Links_Pointing_to_Page(url):
    try:
        search_results = list(search(url, num_results=10))
        return -1 if len(search_results) < 2 else 1
    except:
        return -1

# 30.Statistical Report returns -1 if statistical report is less than 60, otherwise returns 1
def Statistical_Report(url):
    try:
        rank = 0  # implement statistical report algorithm
        return -1 if rank < 60 else 1
    except:
        return -1


# Phishing Website Detection
def Phishing_Website_Detection(url):
    try:
        features = [having_IPhaving_IP_Address(url),
URLURL_Length(url),
Shortining_Service(url),
having_At_Symbol(url),
double_slash_redirecting(url),
Prefix_Suffix(url),
having_Sub_Domain(url),
SSLfinal_State(url),
Domain_registeration_length(url),
Favicon(url),
port(url),
HTTPS_token(url),
Request_URL(url),
URL_of_Anchor(url),
Links_in_tags(url),
SFH(url),
Submitting_to_email(url),
Abnormal_URL(url),
Redirect(url),
on_mouseover(url),
RightClick(url),
popUpWidnow(url),
iFrame(url),
Domain_Age(url),
DNS_Record(url),
Web_Traffic(url),
Page_Rank(url),
Google_Index(url),
Links_Pointing_to_Page(url),
Statistical_Report(url)]
        return features
    except:
        return [-1] * 17

# Example usage:
#url = "http://example.com"
#features = Phishing_Website_Detection(url)
#print(features)