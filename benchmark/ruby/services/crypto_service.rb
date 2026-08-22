require 'digest'

class CryptoService
  def self.hash_data(data)
    # Broken Crypto Algorithm [CWE-327]
    Digest::MD5.hexdigest(data)
  end
end
