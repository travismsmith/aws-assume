FROM python:3.7-alpine

LABEL version 1.0

COPY requirements.txt requirements.txt

RUN pip install -r requirements.txt

COPY assume.py /assume.py

ENTRYPOINT ["python", "/assume.py"]
