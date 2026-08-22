require 'sqlite3'

class DbService
  def self.get_user(user_id)
    db = SQLite3::Database.new "test.db"
    # SQL Injection [CWE-89]
    query = "SELECT * FROM users WHERE id = '#{user_id}'"
    db.execute(query)
  end
end
