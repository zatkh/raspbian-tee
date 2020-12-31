## Docker build environment

The Dockerfile contains Ubuntu dependencies required by OPTEE etc and ARM
toolchains for aarch32 and aarch64.

To build and tag as `sirius-builder`:

$ docker build -t sirius-builder .

To use it as an interative build environment:

```
$ cd ..
$ docker run -it -rm -v $(pwd):$(pwd) -w $(pwd) sirius-builder:latest
```


.. or to run e.g. make (note that build artefacts will be owned by root unless
-u is specified):

```
$ cd ..
$ docker run -it -rm -v $(pwd):$(pwd) -w $(pwd) sirius-builder:latest make
```
