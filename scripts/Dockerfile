FROM fedora

RUN dnf -y install pypy3 pypy3-devel
RUN pypy3 -m ensurepip

COPY ./ /app
WORKDIR /app
ENV PYTHONIOENCODING=utf-8
RUN pypy3 setup.py install

CMD pypy3 scripts/samson-py