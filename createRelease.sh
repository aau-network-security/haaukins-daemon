#!/bin/bash

# This script is used to create a release of the project.
# Check if the -h or --help flag is passed
if [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
  echo "Usage: $0 <version>"
  echo
  echo "This script is used to create a release of the project."
  echo
  echo "Arguments:"
  echo "  <version>  The version number for the release."
  echo
  echo "Options:"
  echo "  -h, --help  Show this help message and exit."
  exit 0
fi

if [ -z "$1" ]; then
  echo "Error: Please provide the version number as an argument."
  echo "Usage: $0 <version>"
  exit 1
fi

mkdir -p release

# First we build the binary with the version tag
echo "Building the project with version $1"
date=$(date)
go build --ldflags "-X 'main.version=$1' -X 'main.compileDate=$date'" -o release/haaukins-daemon-$1-linux-64bit
chmod +x release/haaukins-daemon-$1-linux-64bit

# cp database folder to release
cp -r database release/

# cp config folder to release
cp -r config release/

# cp nginx folder to release
cp -r nginx release/

# cp the systemd service file to release
cp haaukins-daemon.service release/

# cd to release folder
cd release

# Create the tarball
echo "Creating the tarball"
tar -czf haaukins-daemon-$1-linux-64bit.tar.gz haaukins-daemon-$1-linux-64bit database config nginx haaukins-daemon.service

# remove everything exept the build binary and tarball
rm -rf database config nginx haaukins-daemon.service


