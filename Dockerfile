FROM python:3.10-slim-bookworm AS build-base

WORKDIR /build
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends python3-dev build-essential && \
    apt-get clean
RUN pip install --upgrade pip
COPY requirements.txt .
RUN pip install -r /build/requirements.txt

ARG USERNAME=app
RUN adduser --disabled-password ${USERNAME}
WORKDIR /home/${USERNAME}

# Copy the entire project directory into the container
COPY . /home/app

RUN chown -R app:app /home/app && \
    chmod -R 755 /home/app && \
    chmod +x /home/app/entrypoint.sh

USER ${USERNAME}

ENTRYPOINT ["/home/app/entrypoint.sh"]
