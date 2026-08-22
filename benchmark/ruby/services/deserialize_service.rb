class DeserializeService
  def self.load_data(serialized_data)
    # Insecure Deserialization [CWE-502]
    Marshal.load(serialized_data)
  end
end
