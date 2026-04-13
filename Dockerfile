FROM python:3.12-alpine

WORKDIR /app
COPY server.py /app/server.py
RUN addgroup -S app -g 1000 && adduser -S -D -H -u 1000 -G app app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
USER 1000:1000
EXPOSE 8080
CMD ["python3", "/app/server.py"]
