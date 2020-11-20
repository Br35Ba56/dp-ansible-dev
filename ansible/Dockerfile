FROM ubuntu:18.04

RUN /bin/bash -c "apt-get update && apt-get install -y \
                   python3 python3-pip python3-dev python3-venv \
                   build-essential zip git curl"

ENV VIRTUAL_ENV=/opt/venv
ENV PYTHONPATH="/DEV:$PYTHONPATH"
ENV PATH="$VIRTUAL_ENV/bin:$PATH"
RUN python3 -m venv $VIRTUAL_ENV &&  pip install -U pip
RUN pip install ansible
ADD dev/ansible-datapower /DEV