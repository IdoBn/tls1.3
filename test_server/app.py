from flask import Flask
app = Flask(__name__)

@app.route("/", methods=["GET"])
def hello():
    return "Hello World!"

@app.route("/img.jpg", methods=["GET", "HEAD", "POST"])
def test():
    return "also hello"

if __name__ == "__main__":
    app.run()