#modified code

import requests
import re

def check_domain_reputation(api_key, url):
    """Check the domain reputation using Google Safe Browsing API."""
    api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    params = {
        "key": api_key
    }
    body = {
        "client": {
            "clientId": "yourcompanyname",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    
    try:
        response = requests.post(api_url, params=params, json=body)
        response.raise_for_status()  # Raise an error for bad responses
        result = response.json()
        
        if 'matches' in result:
            return False  # Threat found, URL is not safe
        else:
            return True  # No threats found, URL is safe
    
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
        return False
    except Exception as err:
        print(f"An error occurred: {err}")
        return False

def is_social_media_link(url):
    """Check if the given URL is a social media link."""
    # List of known social media domains
    social_media_domains = {
        "facebook.com": "Facebook",
        "twitter.com": "Twitter",
        "instagram.com": "Instagram",
        "linkedin.com": "LinkedIn",
        "youtube.com": "YouTube",
        "tiktok.com": "TikTok",
        "snapchat.com": "Snapchat",
        "pinterest.com": "Pinterest",
        "reddit.com": "Reddit",
        "tumblr.com": "Tumblr",
        "whatsapp.com": "WhatsApp",
        "vk.com": "VK",
        "flickr.com": "Flickr",
        "discord.com": "Discord"
    }
    
    # Regular expression to match the URL
    pattern = re.compile(r'https?://(www\.)?([^/]+)', re.IGNORECASE)
    match = pattern.match(url)
    
    if match:
        domain = match.group(2)  # Extract the domain from the URL
        return social_media_domains.get(domain, None)  # Return the social media name or None
    return None

def social(api_key, url_to_check):
    """Check if the URL is a social media link and its safety."""
    social_media_name = is_social_media_link(url_to_check)
    if social_media_name:
        # Check the domain reputation
        is_safe = check_domain_reputation(api_key, url_to_check)
        
        if is_safe:
            return f"The URL is a social media link ({social_media_name}) and it is safe."
        else:
            return f"The URL is a social media link ({social_media_name}), but it is not safe."
    else:
        return "The URL is NOT a social media link."

if __name__ == "__main__":
    api_key = "AIzaSyDuyr0kocEYAJjgwj8xPT07VLh8vpzExc4"  # Replace with your actual API key
    url_to_check = input("Enter the URL to check: ")
    print(social(api_key, url_to_check))
