FROM python:3.13.1-bullseye

SHELL ["/bin/bash", "-c", "-e"]

USER root


RUN mkdir -p /usr/local/share/ca-certificates
COPY cert/*.crt /usr/local/share/ca-certificates
RUN ls -la /usr/local/share/ca-certificates

RUN chmod 644 /usr/local/share/ca-certificates -R

RUN update-ca-certificates -v

ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
ENV AWS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY . /dist

ENTRYPOINT []
CMD ["python3", "/dist/server.py"] 
