import requests
from flask import Flask, request

app = Flask(__name__)

api_key = '6990852c48f74ed18829596601f96946'  # Spoonacular API KEY
params = {
    'apiKey': api_key
}


@app.route('/')
def hello_world():
    return 'Hello World!'


"""EXAMPLE API CALL - BUILD AROUND THIS"""


@app.route('/api-call/<string:recipe_id>')
def api_call(recipe_id):
    data = request.get_json()
    print(data)
    endpoint = f'https://api.spoonacular.com/recipes/{recipe_id}/ingredientWidget.json'
    response = requests.get(endpoint, params=params)

    return response.json()


if __name__ == '__main__':
    app.run()
