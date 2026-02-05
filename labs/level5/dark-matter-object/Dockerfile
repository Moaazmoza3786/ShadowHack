FROM python:3.9-slim
WORKDIR /app
RUN pip install flask
COPY app.py .
ENV FLAG="AG{D3s3r1al1z4t10n_1s_D3adly_RCE}"
EXPOSE 5000
CMD ["python", "app.py"]
