# main.py
from ryu.base import app_manager
from controller import of_handler

# Start Ryu with your apps
app_manager.AppManager.run_apps([
    "controller.of_handler"
])