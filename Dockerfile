FROM python:2.7
RUN mkdir -p /opt/jenova
RUN mkdir -p /var/log/jenova
WORKDIR /opt/jenova
COPY ./src/jenova /opt/jenova
COPY ./src/test /opt/jenova/test
ADD ./src/requirements.txt /opt/jenova/
RUN pip install -r /opt/jenova/requirements.txt
RUN groupadd -r jenovad && useradd -r -g jenovad jenovad
RUN chown jenovad: /var/log/jenova
RUN chown -R jenovad: /opt/jenova
USER jenovad
CMD ["/bin/bash", "jenovad"]
