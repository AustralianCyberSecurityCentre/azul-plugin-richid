ARG REGISTRY="docker.io/library"
ARG BUILD_IMAGE='python'
ARG BUILD_TAG='3.12-trixie'
ARG BASE_IMAGE='python'
ARG BASE_TAG='3.12-slim-trixie'

FROM $REGISTRY/$BUILD_IMAGE:$BUILD_TAG AS builder
ENV DEBIAN_FRONTEND=noninteractive
ENV PIP_DISABLE_PIP_VERSION_CHECK=yes
ARG PIP_CERT
ARG PIP_CLIENT_CERT
ARG PIP_TRUSTED_HOST
ARG PIP_INDEX_URL
ARG GIT_BRANCH_NAME
ARG PIP_EXTRA_INDEX_URL

COPY debian.txt /tmp/src/
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    $(grep -vE "^\s*(#|$)" /tmp/src/debian.txt | tr "\n" " ") && \
    rm -rf /tmp/src/debian.txt /var/lib/apt/lists/*
# copy all files not in .dockerignore
COPY ./ /tmp/src
RUN pip install build setuptools_scm
# build package
RUN cd /tmp/src && python -m build . --outdir /tmp/
# install package
RUN pip install \
    --find-links /tmp/ \
    # Version specified to ensure the package that was just built is installed instead of a newer version of the package.
    azul-plugin-richid==$(cd /tmp/src && python -m setuptools_scm)

# If on dev branch, install dev versions of azul packages (locate packages)
# Note pip install --pre --upgrade --no-deps is not valid because it doesn't install the requirements of dev azul packages which are needed.
RUN if [ "$GIT_BRANCH_NAME" = "refs/heads/dev" ] ; then \
    pip freeze | grep 'azul-.*==' | cut -d "=" -f 1 | xargs -I {} pip install --find-links /tmp/ --upgrade '{}>=0.0.1.dev' ;fi
# re-run install sdist to get correct version of current package after dev install.
RUN if [ "$GIT_BRANCH_NAME" = "refs/heads/dev" ] ; then \
    pip install --find-links /tmp/ azul-plugin-richid==$(cd /tmp/src && python -m setuptools_scm);fi


FROM $REGISTRY/$BASE_IMAGE:$BASE_TAG AS base
ENV DEBIAN_FRONTEND=noninteractive
COPY debian.txt /tmp/src/
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    $(grep -vE "^\s*(#|$)" /tmp/src/debian.txt | tr "\n" " ") && \
    rm -rf /tmp/src/debian.txt /var/lib/apt/lists/*
ARG UID=21000
ARG GID=21000
RUN groupadd -g $GID azul && useradd --create-home --shell /bin/bash -u $UID -g $GID azul
USER azul
COPY --from=builder /usr/local /usr/local

# run tests during build to verify dockerfile has all requirements
FROM base AS tester
ENV PIP_DISABLE_PIP_VERSION_CHECK=yes
ARG PIP_CERT
ARG PIP_CLIENT_CERT
ARG PIP_TRUSTED_HOST
ARG PIP_INDEX_URL
ARG PIP_EXTRA_INDEX_URL
ARG UID=21000
ARG GID=21000
# test scripts will be installed to the local user bin dir. Add local bin path for the azul user.
ENV PATH="/home/azul/.local/bin:$PATH"
COPY requirements_tests.txt /tmp/src/
RUN pip install -r /tmp/src/requirements_tests.txt
COPY --chown=azul ./tests /tmp/tests
RUN --mount=type=secret,uid=$UID,gid=$GID,id=testSecret export $(cat /run/secrets/testSecret) && \
    python -m pytest --tb=short /tmp/tests
# generate empty file to copy to `release` stage so this stage is not skipped due to optimisations.
RUN touch /tmp/testingpassed

FROM base AS release
# copy from `tester` stage to ensure testing is not skipped due to build optimisations.
COPY --from=tester /tmp/testingpassed /tmp/
ENTRYPOINT ["azul-plugin-richid"]
