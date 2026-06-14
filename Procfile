web: gunicorn app:app --worker-class gthread --workers 1 --threads 8 --max-requests 500 --max-requests-jitter 50 --timeout 120 --graceful-timeout 30 --preload
