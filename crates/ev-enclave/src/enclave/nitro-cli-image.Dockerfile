FROM amazonlinux:2.0.20240529.0


# install Nitro CLI
RUN amazon-linux-extras install aws-nitro-enclaves-cli -y; \
yum install aws-nitro-enclaves-cli-devel -y;

ENTRYPOINT ["nitro-cli"]
