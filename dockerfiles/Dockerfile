FROM bl4ck5un/sgx-rust-fork:2004-1.1.6

RUN useradd -m -s /bin/bash ubuntu && \
    echo "ubuntu ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
RUN chown -R ubuntu:ubuntu /home/ubuntu
RUN echo "root:root" | chpasswd
RUN echo "ubuntu:ubuntu" | chpasswd
EXPOSE 22