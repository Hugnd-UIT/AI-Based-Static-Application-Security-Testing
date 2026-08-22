using System.Xml;

namespace Benchmark.CSharp.Services
{
    public class XmlService
    {
        public void ParseXmlData(string xmlInput)
        {
            // XML External Entity (XXE) [CWE-611]
            XmlReaderSettings settings = new XmlReaderSettings();
            settings.DtdProcessing = DtdProcessing.Parse; 
            
            using (StringReader sr = new StringReader(xmlInput))
            using (XmlReader reader = XmlReader.Create(sr, settings))
            {
                XmlDocument doc = new XmlDocument();
                doc.Load(reader);
            }
        }
    }
}
