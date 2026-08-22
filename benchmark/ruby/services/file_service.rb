class FileService
  def self.read_file(filename)
    # Path Traversal [CWE-22]
    path = "/var/www/uploads/" + filename
    File.read(path)
  end
end
