FROM python:3.13-slim
RUN pip install --no-cache-dir paho-mqtt==2.1.0
COPY mqtt_bridge.py /app/mqtt_bridge.py
WORKDIR /app
ENV PYTHONUNBUFFERED=1
CMD ["python", "mqtt_bridge.py"]
