"""Convenience entry point for running Vulnify backend."""

import uvicorn
from vulnify.main import app

if __name__ == "__main__":
    uvicorn.run("vulnify.main:app", host="127.0.0.1", port=8000, reload=True)
