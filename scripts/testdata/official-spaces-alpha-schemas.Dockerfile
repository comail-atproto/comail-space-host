ARG BASE_IMAGE
FROM ${BASE_IMAGE}

USER root
COPY lexicons/email/atmos/message.json /tmp/comail-schema-source/message.json
COPY lexicons/email/atmos/messageStateRevision.json /tmp/comail-schema-source/messageStateRevision.json
COPY lexicons/email/atmos/messageStateOperation.json /tmp/comail-schema-source/messageStateOperation.json
COPY lexicons/email/atmos/folderRevision.json /tmp/comail-schema-source/folderRevision.json
COPY lexicons/email/atmos/folderOperation.json /tmp/comail-schema-source/folderOperation.json
COPY scripts/testdata/install-official-spaces-alpha-schemas.mjs /tmp/install-official-spaces-alpha-schemas.mjs
RUN node /tmp/install-official-spaces-alpha-schemas.mjs >/tmp/comail-schema-install-result.json

ARG BASE_COMMIT
ARG PATCHED_PREPARE_SHA256
ARG INSTALLER_SHA256
ARG RECIPE_SHA256
ARG SCHEMA_BUNDLE_SHA256
ARG RUN_ID
LABEL comail.proof.base-commit=${BASE_COMMIT} \
      comail.proof.patched-prepare-sha256=${PATCHED_PREPARE_SHA256} \
      comail.proof.installer-sha256=${INSTALLER_SHA256} \
      comail.proof.recipe-sha256=${RECIPE_SHA256} \
      comail.proof.schema-bundle-sha256=${SCHEMA_BUNDLE_SHA256} \
      comail.proof.run=${RUN_ID}
USER node
