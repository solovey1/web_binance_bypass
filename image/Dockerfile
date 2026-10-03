# syntax=docker/dockerfile:1
FROM python:3.12.2
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
WORKDIR /code
COPY image/requirements.txt /code/
RUN  apt-get -y update && apt-get install -y --no-install-recommends python3-dev python3-pip  gcc libldap2-dev libssl-dev libsasl2-dev
RUN  pip install --upgrade pip
RUN pip install -r requirements.txt

