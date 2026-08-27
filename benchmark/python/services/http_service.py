import requests

def fetch_url(url):
    # Server-Side Request Forgery [CWE-918]
    response = requests.get(url)
    return response.text
