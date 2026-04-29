import sys
import os
sys.path.append(os.path.join(os.getcwd(), 'api'))

from app.services.installer_service import get_install_command

try:
    cmd = get_install_command(
        server="http://localhost:8000",
        port=8000,
        token="test-token",
        name="test-agent",
        enable_logs=True,
        enable_fim=False,
        enable_metrics=True
    )
    print("Success!")
    print(cmd)
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
