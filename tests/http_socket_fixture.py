from flask import Flask, request

app = Flask(__name__)


@app.get("/health")
def health():
    return "ok"


@app.post("/echo")
def echo():
    return request.get_data(cache=False)


@app.post("/form")
def form():
    return {"parts": len(request.form)}
