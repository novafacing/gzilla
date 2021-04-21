uid := $(shell awk -F: 'END {print u}{if($$1=="Uid"){split($$2,a," ");u=a[1]}}' /proc/self/status)
gid := $(shell awk -F: 'END {print g}{if($$1=="Gid"){split($$2,a," ");g=a[1]}}' /proc/self/status)

all:
	echo $(uid)
	echo $(gid)
	docker build --rm --build-arg uid=$(uid) --build-arg gid=$(gid) -t firefox .
	docker run -ti --rm -e DISPLAY=${DISPLAY} -v /tmp/.X11-unix:/tmp/.X11-unix firefox

