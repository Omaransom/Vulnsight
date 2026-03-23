import uvicorn
import sys
from pathlib import Path

# Ensure project root is on PYTHONPATH when executed directly
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.core.settings import settings


if __name__ == "__main__":
    uvicorn.run(
        "src.api.server:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=False,
    )
