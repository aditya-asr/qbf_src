FROM ubuntu:22.04

ARG LISTENIP

# Setting up bind

RUN apt update -y
RUN apt upgrade -y
RUN apt update -y
RUN DEBIAN_FRONTEND="noninteractive" TZ="Asia/Kolkata" apt install ssh vim git pkg-config autoconf automake build-essential libnghttp2-dev libtool libtool-bin libuv1-dev libcap-dev libssl-dev iproute2 -y
RUN DEBIAN_FRONTEND="noninteractive" TZ="Asia/Kolkata" apt install astyle cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz -y
RUN git clone --branch OQS-OpenSSL_1_1_1-stable https://github.com/Martyrshot/openssl.git /oqs-openssl-source
RUN git clone https://github.com/open-quantum-safe/liboqs.git
RUN cd liboqs && git checkout af76ca3b1f2fbc1f4f0967595f3bb07692fb3d82
RUN mkdir liboqs/build
RUN cd liboqs/build && cmake -GNinja -DCMAKE_INSTALL_PREFIX=/oqs-openssl-source/oqs ..
RUN cd liboqs/build && ninja
RUN cd liboqs/build && ninja install
RUN cd oqs-openssl-source && ./Configure no-shared linux-aarch64 --prefix=/oqs-openssl -lm
RUN cd oqs-openssl-source && make
RUN cd oqs-openssl-source && make install_sw
RUN git clone https://github.com/aditya-asr/OQS-bind /bind9
ENV LD_LIBRARY_PATH=/usr/local/lib
RUN cd bind9/ && autoreconf -fi
RUN cd bind9/ && ./configure CFLAGS="-Wl,--no-as-needed" LIBS="-loqs -ldl" CPPFLAGS="-I/oqs-openssl-source/oqs/include" LDFLAGS="-L/oqs-openssl/lib -L/oqs-openssl-source/oqs/lib" --with-openssl=/oqs-openssl;
RUN cd bind9/ && make
RUN cd bind9/ && make install
RUN mkdir /usr/local/etc/bind
RUN mkdir /usr/local/etc/bind/zones
RUN mkdir /var/cache/bind
RUN mkdir /setup_files/
COPY install_trust_anchor.bash /setup_files/
COPY named.conf /usr/local/etc
COPY root.hints /usr/local/etc/bind/root/hints/root.hints

# Setting up daemon
RUN apt update
RUN apt install iptables iputils-ping iperf gcc make net-tools iproute2 libnetfilter-queue-dev netcat traceroute vim -y
RUN apt install git libtool libnl-3-dev libnl-genl-3-dev binutils-dev libreadline6-dev autoconf libpcap-dev -y

COPY ./qbf/src /qbf/src
COPY ./qbf/include /qbf/include
COPY ./qbf/c-hashmap /qbf/c-hashmap
COPY ./qbf/makefile /qbf/makefile
WORKDIR /qbf
RUN make daemon
ENV LISTENIP=${LISTENIP}
WORKDIR /
#CMD /setup_files/install_trust_anchor.bash && rm -rf /dsset/* && iptables -A INPUT -p ip -j NFQUEUE --queue-num 0 && iptables -A OUTPUT -p ip -j NFQUEUE --queue-num 0 && ifconfig && ./qbf/daemon ${LISTENIP} --is_resolver & named -g -d 3
