BASE_DIR=$(shell pwd)/..

.PHONY: all dcnet builder push-dcnet push-builder

all: dcnet

dcnet:
	cd ${BASE_DIR} && \
	docker build \
		-t bl4ck5un/dcnet \
		-f dockerfiles/Dockerfile.deploy .

builder:
	cd ${BASE_DIR} && \
	docker build \
		-t bl4ck5un/dcnet-builder \
		-f dockerfiles/Dockerfile.builder .

push-dcnet: dcnet
	docker push bl4ck5un/dcnet

push-builder: builder
	docker push bl4ck5un/dcnet-builder
