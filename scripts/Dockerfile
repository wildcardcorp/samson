FROM pypy:3

COPY ./ /app
WORKDIR /mnt
ENV PYTHONIOENCODING=utf-8
RUN pip install -e /app

CMD pypy3 /app/scripts/samson-py