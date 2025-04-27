import ssl
import urllib.request

def fetch_url(url):
    # Vulnerable: Disabling SSL verification
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    response = urllib.request.urlopen(url, context=context)
    return response.read()

# Example usage
data = fetch_url('https://example.com') 