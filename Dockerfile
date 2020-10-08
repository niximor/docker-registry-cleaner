FROM python:3.8-alpine

# Install dependencies first to avoid re-creation when code changes.
ADD requirements.txt /requirements.txt
RUN pip install -r /requirements.txt

ADD rules.yaml /app/
ADD docker-entrypoint.sh /

ADD src/ /app/

WORKDIR /app
ENTRYPOINT ["/docker-entrypoint.sh"]