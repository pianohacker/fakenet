FROM ubuntu:rolling

RUN apt update && \
	DEBIAN_FRONTEND='noninteractive' apt install --yes python3 python3-pip libpcap0.8 && \
	apt clean -yy && rm -rf /var/lib/apt/lists

RUN pip install pipenv

RUN mkdir /mnt/acceptance
WORKDIR /mnt/acceptance
COPY Pipfile /mnt/acceptance
COPY Pipfile.lock /mnt/acceptance
RUN pipenv install
WORKDIR /
RUN rm -rf /mnt/acceptance

ENTRYPOINT ["/bin/bash"]
