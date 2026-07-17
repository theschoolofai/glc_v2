import os

from glc.dev_env import load_only

load_only('GEMINI_API_KEY')
print('GEMINI_API_KEY =', os.environ.get('GEMINI_API_KEY'))
