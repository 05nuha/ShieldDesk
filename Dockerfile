FROM python:3.12-slim
WORKDIR /srv
RUN pip install --no-cache-dir flask==3.1.* faker requests
ARG SEED_MODE=secure
COPY app/ /srv/
RUN python3 seed.py ${SEED_MODE} && useradd -m shield && chown -R shield /srv
USER shield
ENV SHIELDDESK_HOST=0.0.0.0
EXPOSE 5000
CMD ["python3", "app.py"]
