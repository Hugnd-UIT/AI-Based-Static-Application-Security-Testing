SINKS = [
    # Đa ngôn ngữ
    "execute", "query", "exec", "rawQuery", "ExecuteNonQuery", "ExecuteReader", "executeQuery", "executeUpdate",
    
    # Python
    "subprocess.run", "subprocess.Popen", "subprocess.call", "os.system", "os.popen", 
    "render_template_string", "pickle.loads", "yaml.load", "pickle.load", "marshal.loads", 
    "shelve.open", "jsonpickle.decode", "__reduce__",
    
    # JavaScript
    "innerHTML", "outerHTML", "document.write", "document.writeln", "insertAdjacentHTML", "Function(",
    "child_process.exec", "child_process.spawn", "child_process.execSync", "fs.readFile", "fs.writeFile", 
    "fs.appendFile", "fs.unlink", "res.send", "res.json", "res.end", "res.redirect", "res.location",
    
    # PHP
    "system", "popen", "shell_exec", "eval", "exec", "passthru", "preg_replace", "create_function", 
    "assert", "include", "require", "include_once", "file_get_contents",
    
    # Java
    "Runtime.exec", "ProcessBuilder", "ScriptEngine.eval", "Class.forName", "Method.invoke",
    "InitialContext.lookup", "Context.lookup", "ldap://",
    
    # Go
    "os.Exec", "exec.Command", "exec.CommandContext", "ioutil.WriteFile", "os.WriteFile",
    
    # Ruby
    "open", "send", "`",
    
    # C/C++
    "strcpy", "sprintf", "gets", "memcpy", "strcat", "execl", "execv", "printf", "fopen", "unlink", "remove",
]