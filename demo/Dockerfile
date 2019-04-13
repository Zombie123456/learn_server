FROM python:3.6.2
ENV PYTHONUNBUFFERED 1
RUN mkdir /docker_api
WORKDIR /docker_api
EXPOSE 8000
COPY . /docker_api/
RUN pip install -r requirements.txt
COPY . .
ENTRYPOINT ["/docker_api/entrypoint.sh"]