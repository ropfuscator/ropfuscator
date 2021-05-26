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
COPY codegen.sh /opt/tigress

WORKDIR /opt/tigress

ENV PATH="${PATH}:/opt/tigress/3.1"
ENV TIGRESS_HOME="/opt/tigress/3.1"
ENV TIGRESS_ENV="x86_64:Linux:Gcc:4.6"
ENV TIGRESS_SEED=20210609125959

ENV TIGRESS_RANDOM_FUNS_ARGS="--Environment=${TIGRESS_ENV} \
    --Seed=${TIGRESS_SEED} \
    --Transform=RandomFuns \
    --Verbosity=5 \
    --RandomFunsName=crackme \
    --RandomFunsFunctionCount=1 \
    --RandomFunsType=char \
    --RandomFunsInputSize=1 \
    --RandomFunsOutputSize=1 \
    --RandomFunsBoolSize=50 \
    --RandomFunsLocalDynamicStateSize=50 \
    --RandomFunsGlobalStaticStateSize=50 \
    --RandomFunsGlobalDynamicStateSize=50 \
    --RandomFunsLocalStaticStateSize=50 \
    --RandomFunsActivationCodeCheckCount=1 \
    --RandomFunsFailureKind=message"

ENV TIGRESS_OBFUSCATION_ARGS="--Seed=${TIGRESS_SEED} \
    --Environment=${TIGRESS_ENV} \
    --Transform=InitEntropy \
    --Functions=main\
    --Transform=InitOpaque \
    --Functions=main --InitOpaqueCount=1 --InitOpaqueStructs=list,array\
    --Transform=EncodeLiterals \
    --Functions=crackme_1 --EncodeLiteralsKinds=string --EncodeLiteralsEncoderName=STRINGS\
    --Transform=Virtualize \
    --Functions=STRINGS --VirtualizeDispatch=switch --VirtualizeOperands=stack,registers \
    --VirtualizeMaxMergeLength=2 --VirtualizeSuperOpsRatio=1.0 \
    --Transform=AddOpaque \
    --Functions=crackme_1 --AddOpaqueKinds=call,bug,true --AddOpaqueCount=4\
    --Transform=Virtualize \
    --Functions=crackme_1 --VirtualizeDispatch=indirect --VirtualizeOperands=stack,registers \
    --VirtualizeMaxMergeLength=2 --VirtualizeSuperOpsRatio=1.0 \
    --Transform=Virtualize \
    --Functions=crackme_1 --VirtualizeDispatch=ifnest --VirtualizeOperands=stack,registers \
    --VirtualizeMaxMergeLength=2 --VirtualizeSuperOpsRatio=1.0 --VirtualizeNumberOfBogusFuns=1\
    --Transform=EncodeLiterals \
    --Functions=crackme_1 --EncodeLiteralsKinds=integer"

RUN ./codegen.sh