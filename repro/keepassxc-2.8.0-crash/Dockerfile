# Throwaway KeePassXC 2.8.0 (tag 2.8.0, commit 1c2f23ef) built with debug info, to reproduce
# the crash described in UPSTREAM-REPORT.md. Never the user's KeePassXC: own socket, own database.
FROM debian:trixie
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build git ca-certificates pkg-config \
    qt6-base-dev qt6-base-private-dev qt6-svg-dev qt6-tools-dev qt6-tools-dev-tools qt6-l10n-tools \
    libbotan-2-dev zlib1g-dev libminizip-dev libpcsclite-dev libxi-dev libxtst-dev \
    libqrencode-dev libargon2-dev libreadline-dev libgl-dev libxkbcommon-dev \
    xvfb xauth dbus dbus-x11 gdb xdotool x11-utils \
    libusb-1.0-0-dev libpolkit-gobject-1-dev libpolkit-agent-1-dev libglib2.0-dev libkeyutils-dev asciidoctor \
    libxcb-cursor0 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 libxcb-render-util0 libxcb-shape0 libxcb-xkb1 libxkbcommon-x11-0 libxcb-xinerama0 \
 && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch 2.8.0 https://github.com/keepassxreboot/keepassxc /src
RUN cmake -S /src -B /build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DWITH_XC_ALL=OFF -DWITH_XC_BROWSER=ON -DWITH_XC_NETWORKING=OFF -DWITH_TESTS=OFF \
      -DWITH_XC_DOCS=OFF -DWITH_XC_KEESHARE=OFF -DWITH_XC_FDOSECRETS=OFF -DWITH_XC_SSHAGENT=OFF -DWITH_XC_UPDATECHECK=OFF \
      -DWITH_XC_AUTOTYPE=OFF -DWITH_XC_YUBIKEY=OFF -DKEEPASSXC_BUILD_TYPE=Snapshot -DCMAKE_CXX_FLAGS="-g1" \
 && cmake --build /build -j6
