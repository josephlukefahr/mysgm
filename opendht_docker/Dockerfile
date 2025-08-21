FROM ubuntu:24.04

LABEL maintainer="Adrien Béraud <adrien.beraud@savoirfairelinux.com>"
LABEL org.opencontainers.image.source=https://github.com/savoirfairelinux/opendht

RUN apt-get update && apt-get install -y \
        dialog apt-utils \
    && apt-get clean \
    && echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections

RUN apt-get update && apt-get install -y \
        build-essential pkg-config cmake git wget meson \
        libtool autotools-dev autoconf \
        python3-dev python3-setuptools python3-build python3-virtualenv cython3 \
        libncurses5-dev libreadline-dev nettle-dev libcppunit-dev \
        libgnutls28-dev libuv1-dev libjsoncpp-dev libargon2-dev \
        libssl-dev libfmt-dev libasio-dev libmsgpack-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/* /var/cache/apt/*

RUN mkdir /usr/include/nonstd \
    && wget https://raw.githubusercontent.com/martinmoene/expected-lite/master/include/nonstd/expected.hpp \
            -O /usr/include/nonstd/expected.hpp

RUN echo "*** Downloading RESTinio 0.7.3 ***" \
    && mkdir restinio && cd restinio \
    && wget https://github.com/Stiffstream/restinio/releases/download/v.0.7.3/restinio-0.7.3.tar.bz2 \
    && ls -l && tar -xjf restinio-0.7.3.tar.bz2 \
    && cd restinio-0.7.3/dev \
    && cmake -DCMAKE_INSTALL_PREFIX=/usr -DRESTINIO_TEST=Off -DRESTINIO_SAMPLE=Off -DRESTINIO_BENCHMARK=Off \
             -DRESTINIO_WITH_SOBJECTIZER=Off -DRESTINIO_DEP_STANDALONE_ASIO=system -DRESTINIO_DEP_LLHTTP=system \
             -DRESTINIO_DEP_FMT=system -DRESTINIO_DEP_EXPECTED_LITE=system . \
    && make -j2 && make install \
    && cd ../../ && rm -rf restinio*

RUN echo "*** Downloading OpenDHT 3.5.1 ***" \
    && mkdir opendht && cd opendht \
    && wget https://github.com/savoirfairelinux/opendht/archive/refs/tags/v3.5.1.tar.gz \
    && ls -l && tar -xzf v3.5.1.tar.gz \
    && cd opendht-3.5.1 \
    && mkdir build && cd build \
	&& cmake .. -DCMAKE_INSTALL_PREFIX=/usr \
				-DCMAKE_INTERPROCEDURAL_OPTIMIZATION=On \
				-DOPENDHT_C=On \
				-DOPENDHT_PEER_DISCOVERY=On \
				-DOPENDHT_PYTHON=On \
				-DOPENDHT_TOOLS=On \
				-DOPENDHT_PROXY_SERVER=On \
				-DOPENDHT_PROXY_CLIENT=On \
				-DOPENDHT_SYSTEMD=On \
	&& make -j8 && make install \
	&& cd ../../.. && rm -rf opendht
    