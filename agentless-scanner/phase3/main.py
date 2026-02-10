from fastapi import FastAPI, Request, HTTPException

app = FastAPI()

@app.get("/secure")
def secure_endpoint(request: Request):
    user = request.headers.get("X-Remote-User")
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")

    return {"user": user}
