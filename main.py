from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel


app = FastAPI()


all_http_packets = []


@app.post("/{id}")
def http_getter(id: str):
    all_http_packets.append(id)
    print(all_http_packets)
