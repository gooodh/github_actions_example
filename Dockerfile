# pull official base image
FROM python:3.13-slim-bookworm AS builder

# set work directory
WORKDIR /usr/src/app

# set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# install system dependencies and upgrade pip in one layer
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc && \
    pip install --upgrade pip && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /usr/src/app/wheels

# install python dependencies as wheels
COPY ./requirements.txt .
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /usr/src/app/wheels -r requirements.txt && \
    rm -rf /root/.cache/pip  # clean pip cache

#########
# FINAL #
#########

# pull official base image
FROM python:3.13-slim-bookworm

# create the app user
RUN groupadd --system app && \
    adduser --system --group app --home /home/app && \
    mkdir -p /home/app/web

# set environment variables
ENV HOME=/home/app \
    APP_HOME=/home/app/web \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR $APP_HOME

# copy and install wheels (no apt needed)
COPY --from=builder /usr/src/app/wheels /tmp/wheels
RUN pip install --no-cache-dir --no-deps /tmp/wheels/* && \
    rm -rf /tmp/wheels

# copy project with chown
COPY --chown=app:app . $APP_HOME

# change to the app user
USER app
