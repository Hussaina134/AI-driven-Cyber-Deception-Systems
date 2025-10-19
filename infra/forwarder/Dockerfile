
FROM python:3.11-slim
WORKDIR /app
COPY forwarder.py /app/forwarder.py
RUN pip install pymongo python-dateutil watchdog
CMD ["python", "forwarder.py"]

