class SystemUtil
  def self.run_ping(ip_address)
    # Command Injection [CWE-78]
    `ping -c 4 #{ip_address}`
  end
end
