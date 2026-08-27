from flask import render_template_string

def render_user(name):
    # Server-Side Template Injection [CWE-94]
    template = "<h1>Welcome, " + name + "</h1>"
    return render_template_string(template)
