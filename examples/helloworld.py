from callpy import CallFlow
app = CallFlow('helloworld')

@app.route('/')
@app.route('/<foo>/bar')
def hello_world(request, foo):
    return 'Hello World!'

@app.route('/<foo2>/noarg')
def hello_world2(request, foo2):
    return 'Hello World!'

@app.route('/<int:number>/num')
def hello_world3(request, number):
    return 'Hello World! %s'%(number)


if __name__ == '__main__':
    app.run()