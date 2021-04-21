FROM ubuntu:18.04
RUN apt-get update && \
        apt-get install -y \
        firefox

# Replace 0 with your user / group id
ARG uid=0
ARG gid=0
#RUN export uid=0 gid=0
RUN mkdir -p /home/developer
RUN echo "developer:x:${uid}:${gid}:Developer,,,:/home/developer:/bin/bash" >> /etc/passwd
RUN echo "developer:x:${uid}:" >> /etc/group
RUN echo "developer ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
RUN chmod 0440 /etc/sudoers
RUN chown ${uid}:${gid} -R /home/developer

USER developer
ENV HOME /home/developer
CMD /usr/bin/firefox
