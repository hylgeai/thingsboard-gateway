FROM python:3.11-slim AS build

ARG TARGETPLATFORM
ARG BUILDPLATFORM
# 保证 requirements.txt 被复制进镜像
COPY requirements.txt /home/requirements.txt

# 然后再执行安装
# RUN python3 -m pip install --no-cache-dir -r /tmp/requirements.txt
COPY ./thingsboard_gateway /thingsboard_gateway
COPY . .

ENV PATH="/root/.cargo/bin:/root/.local/bin:$PATH" \
    PYTHONPATH="." \
    configs="/thingsboard_gateway/config" \
    extensions="/thingsboard_gateway/extensions" \
    logs="/thingsboard_gateway/logs"

RUN pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple
RUN mkdir -p /default-config/config /default-config/extensions/ &&  \
    cp -r /thingsboard_gateway/config/* /default-config/config/ &&  \
    cp -r /thingsboard_gateway/extensions/* /default-config/extensions &&  \
    echo "Running on $BUILDPLATFORM, building for $TARGETPLATFORM" > /log && \
    echo "deb http://mirrors.aliyun.com/debian bookworm main contrib non-free\n\
deb http://mirrors.aliyun.com/debian bookworm-updates main contrib non-free" > /etc/apt/sources.list && \
    case "$TARGETPLATFORM" in \
        "linux/amd64") DEFAULT_HOST="x86_64-unknown-linux-gnu";; \
        "linux/386") DEFAULT_HOST="i686-unknown-linux-gnu";; \
        "linux/arm64") DEFAULT_HOST="aarch64-unknown-linux-gnu";; \
        "linux/arm/v7") DEFAULT_HOST="armv7-unknown-linux-gnueabihf";; \
        *) \
            echo "Unsupported platform detected. Trying to use default value...";; \
        esac && \
    echo '#!/bin/sh\n\
# Main start script\n\
CONF_FOLDER="/thingsboard_gateway/config"\n\
FIRSTLAUNCH="${CONF_FOLDER}/.firstlaunch"\n\
if [ ! -f "$FIRSTLAUNCH" ]; then\n\
    cp -r /default-config/config/* /thingsboard_gateway/config/\n\
    cp -r /default-config/extensions/* /thingsboard_gateway/extensions/\n\
    touch $FIRSTLAUNCH\n\
    echo "#Remove this file only if you want to recreate default config files! This will overwrite existing files" > $FIRSTLAUNCH\n\
fi\n\
echo "nameserver 8.8.8.8" >> /etc/resolv.conf\n\
python /thingsboard_gateway/tb_gateway.py' > /start-gateway.sh && chmod +x /start-gateway.sh && \
    python3 -m pip install --no-cache-dir --upgrade pip setuptools wheel && \
    python3 -m pip install --no-cache-dir cryptography && \
    python3 -m pip install --no-cache-dir -r requirements.txt && \
    python3 -m pip list

RUN python3 -m pip install --no-cache-dir -r /home/requirements.txt
VOLUME ["${configs}", "${extensions}", "${logs}"]

CMD [ "/bin/sh", "/start-gateway.sh" ]