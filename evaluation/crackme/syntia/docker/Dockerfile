FROM debian:8

RUN apt-get update && apt-get install -y \
    build-essential \
    libffi-dev \
    libglib2.0-dev \
    python-dev \
    python-pip \
    python-setuptools \
    unzip

RUN pip2 install z3-solver==4.5.1.0
RUN pip2 install capstone==4.0.2
RUN pip2 install unicorn==1.0.1

RUN pip2 install elfesteem==0.2.1
RUN pip2 install orderedset==2.0.3
RUN pip2 install pyparsing==2.4.7

WORKDIR /usr/src

# miasm
ADD https://github.com/cea-sec/miasm/archive/v0.0.1.zip /usr/src/miasm.zip
RUN unzip miasm.zip && \
    mv miasm-* miasm && \
    cd miasm && \
    python2 setup.py build && \
    python2 setup.py install && \
    cd .. && \
    rm -rf miasm

# syntia
ADD https://github.com/RUB-SysSec/syntia/archive/36028935cac1a62a8909c1e46a1d818b7c2a43b4.zip /usr/src/syntia.zip
RUN unzip syntia.zip && \
    mv syntia-* syntia && \
    cd syntia && \
    python2 setup.py build && \
    python2 setup.py install && \
    cd ..

