import uvicorn

if __name__ == "__main__":
    uvicorn.run("live_platform.app:app", host="0.0.0.0", port=8000, reload=True)
