# Build from the repository root:
#   docker build -f api/Dockerfile -t sbom-risk-engine .
#   docker run -p 8080:8080 sbom-risk-engine      -> http://localhost:8080/docs
FROM python:3.11-slim
WORKDIR /app
COPY api/requirements.txt /app/api/requirements.txt
RUN pip install --no-cache-dir -r /app/api/requirements.txt
COPY engine/ /app/engine/
COPY api/ /app/api/
COPY site/model_meta.json /app/site/model_meta.json
COPY site/data/ /app/site/data/
ENV PYTHONPATH=/app
EXPOSE 8080
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8080"]
