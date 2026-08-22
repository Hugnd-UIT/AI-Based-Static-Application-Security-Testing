using System.DirectoryServices;

namespace Benchmark.CSharp.Services
{
    public class LdapService
    {
        public void FindUser(string username)
        {
            // LDAP Injection [CWE-90]
            DirectoryEntry entry = new DirectoryEntry("LDAP://OU=Users,DC=example,DC=com");
            DirectorySearcher searcher = new DirectorySearcher(entry);
            
            searcher.Filter = "(sAMAccountName=" + username + ")";
            SearchResult result = searcher.FindOne();
        }
    }
}
