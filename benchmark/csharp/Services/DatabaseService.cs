using System.Data.SqlClient;

namespace Benchmark.CSharp.Services
{
    public class DatabaseService
    {
        public void GetUserById(string id)
        {
            using (SqlConnection connection = new SqlConnection("Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=myPassword;"))
            {
                // SQL Injection [CWE-89]
                string query = "SELECT * FROM Users WHERE Id = '" + id + "'";
                SqlCommand command = new SqlCommand(query, connection);
                
                connection.Open();
                command.ExecuteReader();
            }
        }
    }
}
