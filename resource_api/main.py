# resource_api/main.py

from fastapi import FastAPI

app = FastAPI()

@app.get("/secret")
def get_secret():
    return {
        "data": "this is the protected secret resource",
        "message": "you passed all zero trust checks — welcome"
    }