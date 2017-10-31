
FROM centos:7
RUN yum install git wget -y
RUN wget https://storage.googleapis.com/golang/go1.8.3.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf go*.tar.gz
ENV PATH=$PATH:/usr/local/go/bin
RUN mkdir -p /go/src
ENV GOPATH=/go
RUN go version
RUN wget https://bootstrap.pypa.io/get-pip.py --no-check-certificate
RUN python get-pip.py
RUN pip install awscli
RUN go get github.com/aws/aws-sdk-go/aws/session
RUN go get github.com/aws/aws-sdk-go/service/sts
RUN go get github.com/aws/aws-sdk-go/aws
RUN go get github.com/aws/aws-sdk-go/aws/ec2metadata
RUN go get github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds
RUN go get github.com/aws/aws-sdk-go/aws/credentials
RUN go get github.com/inconshreveable/log15
RUN go get github.com/mattn/go-isatty
RUN mkdir -p ~/src/gossamer
WORKDIR ~/src/gossamer/
COPY . .
RUN chmod +x build.sh