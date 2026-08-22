SOURCES = [
    # Python
    "request.args", "request.form", "request.json", "request.data",
    "request.values", "request.cookies", "request.headers",
    "request.GET", "request.POST", "request.body", "request.META",
    "os.environ", "sys.argv", "os.getenv",
    "socket.recv", "socket.recvfrom", "socket.recvmsg",
    
    # JavaScript
    "req.query", "req.body", "req.params", "req.headers", "req.cookies",
    "ctx.query", "ctx.request", "event.data", "event.target.value", 
    "location.search", "location.hash", "location.href", "document.cookie",
    "window.name", "postMessage",
    
    # PHP
    "$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER", "$_FILES", "$_ENV", "$_SESSION",
    
    # Ruby
    "params[", "request.env", "params[:", "request.params",
    
    # Java
    "getParameter", "getHeader", "getCookies",
    
    # C#
    "Request.Query", "Request.Form", "Request.Headers", "Request.QueryString", "HttpContext.Request",
    
    # Java
    "@PathVariable", "@RequestParam", "@RequestBody",
    "HttpServletRequest.getParameter", "HttpServletRequest.getHeader",
    "HttpServletRequest.getInputStream",
    
    # Go
    "r.URL.Query()", "r.FormValue", "r.PostFormValue",
    "r.Header.Get", "r.Body",
    "gin.Context.Query", "gin.Context.PostForm", "gin.Context.Param",
    "echo.Context.QueryParam", "echo.Context.FormValue",
    
    # C/C++ 
    "getenv", "gets", "scanf", "fscanf", "recv", "recvfrom", "fread", "read", "std::cin", "getline",
    "fgets", "getchar", "readlink", "readdir",

    # Cloud
    "event.body", "event.queryStringParameters",
    "event.pathParameters", "context.clientContext",
]
