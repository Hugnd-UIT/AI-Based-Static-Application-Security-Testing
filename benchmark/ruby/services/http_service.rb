require 'net/http'
require 'uri'

class HttpService
  def self.fetch_url(target_url)
    # Server-Side Request Forgery (SSRF) [CWE-918]
    uri = URI.parse(target_url)
    response = Net::HTTP.get_response(uri)
    response.body
  end
end
