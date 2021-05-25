FROM ubuntu:18.04

RUN apt-get update && apt-get install -y \
    gcc-multilib \
    g++-multilib \
    unzip \
    perl \
    && rm -rf /var/lib/apt/lists/*

COPY tigress-3.1-bin.zip /tmp
WORKDIR /opt

RUN unzip /tmp/tigress-3.1-bin.zip 
RUN ln -s /opt/tigress/3.1/tigress.h /opt/tigress

COPY empty_template.c /opt/tigress
WORKDIR /opt/tigress

ENV PATH="${PATH}:/opt/tigress/3.1"
ENV TIGRESS_HOME="/opt/tigress/3.1"
ENV TIGRESS_ENV="x86_64:Linux:Gcc:4.6"
ENV TIGRESS_SEED=1234

ENV TIGRESS_RANDOM_FUNS_ARGS="--Environment=${TIGRESS_ENV} \
    --Seed=${TIGRESS_SEED} \
    --Transform=RandomFuns \
    --Verbosity=5 \
    --RandomFunsName=crackme \
    --RandomFunsFunctionCount=1 \
    --RandomFunsType=char \
    --RandomFunsInputSize=1 \
    --RandomFunsOutputSize=1 \
    --RandomFunsLoopSize=10 \
    --RandomFunsActivationCodeCheckCount=1 \
    --RandomFunsFailureKind=message"

RUN tigress ${TIGRESS_RANDOM_FUNS_ARGS} --out=daje.c empty_template.c