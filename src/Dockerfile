FROM python:2.7
RUN mkdir -p /opt/jenova
RUN mkdir -p /var/log/jenova
WORKDIR /opt/jenova
ADD requirements.txt /opt/jenova/
RUN pip install -r /opt/jenova/requirements.txt

RUN groupadd -r jenovad && useradd -r -g jenovad jenovad
RUN chown jenovad: /var/log/jenova
USER jenovad
CMD ["/bin/bash", "jenovad"]
