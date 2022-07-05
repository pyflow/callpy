from callpy import CallFlow

app = CallFlow()

@app.route('/')
async def hello(request):
    return 'ok'

app.static('/static', '.')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)