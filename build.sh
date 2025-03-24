#!/bin/bash

VERSION="1.0"
COMMIT=$(git rev-parse HEAD)
DATE=$(date +"%Y%m%d")

VERSION_STRING="$VERSION-$DATE-commit:$COMMIT"

go build -ldflags="-X main.AppVersion=$VERSION_STRING" -o ./release
