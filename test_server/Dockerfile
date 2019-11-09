FROM nginx:latest

RUN apt update
RUN apt install -y openssl

COPY ./content/* /usr/share/nginx/html/

RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/nginx-selfsigned.key \
    -out /etc/ssl/certs/nginx-selfsigned.crt \
    -subj '/CN=US'

COPY ./default.conf /etc/nginx/conf.d/default.conf

RUN apt install -y python3.7 procps python3-pip

RUN python3.7 -m pip install flask

COPY ./app.py /
COPY ./start.sh /

CMD ["bash", "/start.sh"]