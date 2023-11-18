# Create directory for certificates if it doesn't exist
import os
from django.conf import settings

# Define the directory path
dir_path = os.path.join(settings.BASE_DIR, 'keys', 'certificates', 'CA')

# Create the directory if it doesn't exist
os.makedirs(dir_path, exist_ok=True)