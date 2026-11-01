FROM golang@sha256:dc9ad6c05acc7a88e5b71bde60a5fe3bd4b9f0db209011711b464107438a8107 AS go_toolchain
FROM ghcr.io/ansible-community/community-ee-minimal@sha256:41c6c5eeb9915fec5a97de241b2f91a269234942eaa0d78ac5bcead95a0d91b1
COPY --from=go_toolchain /usr/local/go /opt/go
USER 0
COPY ansible.cfg launch.py probe.py profile.lock.json /opt/pilot-controller/
ADD --checksum=sha256:5ff232cf69492a991f2a0990dbb23ef25a600b7e9209de6e33377a6ff08a8a29 https://galaxy.ansible.com/api/v3/plugin/ansible/content/published/collections/artifacts/ansible-posix-2.1.0.tar.gz /opt/pilot-controller/ansible-posix.tar.gz
RUN ansible-galaxy collection install --offline --no-deps -p /opt/pilot-controller/collections /opt/pilot-controller/ansible-posix.tar.gz
RUN mkdir -p /opt/pilot-controller/empty /opt/pilot-bin \
    && printf 'pilot-controller:x:1000:1000:Pilot controller:/tmp/controller/home:/sbin/nologin\n' >> /etc/passwd \
    && printf 'pilot-controller:x:1000:\n' >> /etc/group
ENTRYPOINT ["/usr/bin/python3", "-I", "/opt/pilot-controller/launch.py"]
