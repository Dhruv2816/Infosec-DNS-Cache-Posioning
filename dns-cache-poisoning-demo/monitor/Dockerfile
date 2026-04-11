FROM python:3.9-slim

RUN pip install flask

WORKDIR /app

COPY . .

EXPOSE 8080

ENTRYPOINT ["python", "monitor.py"]
