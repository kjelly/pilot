FROM golang@sha256:dc9ad6c05acc7a88e5b71bde60a5fe3bd4b9f0db209011711b464107438a8107 AS go_toolchain
FROM ghcr.io/ansible-community/community-ee-minimal@sha256:41c6c5eeb9915fec5a97de241b2f91a269234942eaa0d78ac5bcead95a0d91b1
COPY --from=go_toolchain /usr/local/go /opt/go
USER 0
COPY ansible.cfg launch.py probe.py profile.lock.json /opt/pilot-controller/
RUN mkdir -p /opt/pilot-controller/empty /opt/pilot-bin \
    && printf 'pilot-controller:x:1000:1000:Pilot controller:/tmp/controller/home:/sbin/nologin\n' >> /etc/passwd \
    && printf 'pilot-controller:x:1000:\n' >> /etc/group
ENTRYPOINT ["/usr/bin/python3", "-I", "/opt/pilot-controller/launch.py"]
