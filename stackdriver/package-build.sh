#!/bin/bash -xe
<<<<<<< HEAD
<<<<<<< HEAD
VERSION=5.5.2

if [ "x$BRANCH" == "x" ]
then
    BRANCH=stackdriver-agent-$VERSION
fi
=======
VERSION=5.5.0
>>>>>>> stackdriver install and readme
=======
VERSION=5.5.2
>>>>>>> Bump package versions to 5.5.2.

if [ "x$BRANCH" == "x" ]
then
    BRANCH=stackdriver-agent-$VERSION
fi

if [ "x$PKGFORMAT" == "xdeb" ]
then
    # debian denotes 64 arches with amd64
    [ "x$ARCH" == "xx86_64" ] && ARCH="amd64" || true
<<<<<<< HEAD
<<<<<<< HEAD
    git clone git@github.com:Stackdriver/agent-deb.git --branch $BRANCH
    pushd agent-deb
    make clean
    make DISTRO="$DISTRO" ARCH="$ARCH" VERSION="$VERSION" BUILD_NUM="$BUILD_NUM" build || exit $?
    popd
    [ -d result ] && rm -rf result || true
    cp -r agent-deb/result .
elif [ "x$PKGFORMAT" == "xrpm" ]
then
    git clone git@github.com:Stackdriver/agent-rpm.git --branch $BRANCH
    pushd agent-rpm
    make clean
    make DISTRO="$DISTRO" ARCH="$ARCH" VERSION="$VERSION" BUILD_NUM="$BUILD_NUM" build || exit $?
    popd
    [ -d result ] && rm -rf result || true
    cp -r agent-rpm/result .
=======
    git clone git@github.com:Stackdriver/agent-deb.git
=======
    git clone git@github.com:Stackdriver/agent-deb.git --branch $BRANCH
>>>>>>> Change package-build.sh so that it checks out a branch specified by an
    pushd agent-deb
    make clean
    make DISTRO="$DISTRO" ARCH="$ARCH" VERSION="$VERSION" BUILD_NUM="$BUILD_NUM" build || exit $?
    popd
    [ -d result ] && rm -rf result || true
    cp -r agent-deb/result .
elif [ "x$PKGFORMAT" == "xrpm" ]
then
    git clone git@github.com:Stackdriver/agent-rpm.git --branch $BRANCH
    pushd agent-rpm
    make clean
    make DISTRO="$DISTRO" ARCH="$ARCH" VERSION="$VERSION" BUILD_NUM="$BUILD_NUM" build || exit $?
    popd
    [ -d result ] && rm -rf result || true
<<<<<<< HEAD
	cp -r agent-rpm/result .
>>>>>>> stackdriver install and readme
=======
    cp -r agent-rpm/result .
>>>>>>> Changed exit behaviour to return correct exit value. Formatting fix
else
    echo "I don't know how to handle label '$PKGFORMAT'. Aborting build"
    exit 1
fi

