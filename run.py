import uvicorn
from app.api.main import app
from app.core.config import settings

if __name__ == "__main__":
    uvicorn.run(app, host=settings.api_host, port=settings.api_port)
