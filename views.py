def index():
    with open('templates/index.html') as template:
        return template.read()
