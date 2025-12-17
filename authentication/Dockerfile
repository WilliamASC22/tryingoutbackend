FROM python:3.8

ENV HOME /root
WORKDIR /root

COPY ./requirements.txt ./requirements.txt
COPY ./util ./util
COPY ./authentication/authentication.py ./authentication.py
COPY ./authentication/jwtRS256.key ./jwtRS256.key
COPY ./jwtRS256.key.pem ./jwtRS256.key.pem
COPY ./public ./public

RUN pip3 install -r ./requirements.txt

ADD https://github.com/ufoscout/docker-compose-wait/releases/download/2.2.1/wait /wait
RUN chmod +x /wait

CMD /wait && python3 -u authentication.py
