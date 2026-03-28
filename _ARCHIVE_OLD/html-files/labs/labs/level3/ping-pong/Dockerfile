FROM python:3.9-slim
WORKDIR /app
RUN pip install flask
COPY app.py .
RUN echo "AG{C0mm4nd_Inj3ct10n_1s_L3th4l}" > /root/flag.txt
EXPOSE 5000
CMD ["python", "app.py"]
