FROM node:24-alpine@sha256:8a32c8cf649a49915a66e81e7a609223c708d0adabf288ee3f4077d765542f85 AS runtime-files
# The dependency-free runtime needs Node, not bundled package managers.
RUN rm -rf /usr/local/lib/node_modules /opt/yarn* \
    /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack \
    /usr/local/bin/yarn /usr/local/bin/yarnpkg

# Copy the cleaned filesystem so removed packages are absent from final layers.
FROM scratch
COPY --from=runtime-files / /
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
WORKDIR /app
COPY --chown=node:node package.json server.js healthcheck.js ./
USER node
EXPOSE 3000
HEALTHCHECK --interval=3s --timeout=3s --start-period=3s --retries=3 CMD ["node", "healthcheck.js"]
CMD ["node", "server.js"]
