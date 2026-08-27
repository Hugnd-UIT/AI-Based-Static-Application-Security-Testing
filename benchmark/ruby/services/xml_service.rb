require 'nokogiri'

class XmlService
  def self.parse_xml(xml_data)
    # XML External Entity [CWE-611]
    doc = Nokogiri::XML(xml_data) do |config|
      config.noent
    end
    doc.to_s
  end
end
