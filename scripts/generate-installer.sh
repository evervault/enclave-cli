#!/bin/sh

pattern="s/{{version}}/$1/"
major_pattern="s/{{major}}/$2/"
domain_pattern="s/{{domain}}/$3/"

sed -e "$pattern" ./scripts/install.template > ./scripts/install-temp
sed -e "$domain_pattern" ./scripts/install-temp > ./scripts/install-temp-domain
sed -e "$major_pattern" ./scripts/install-temp-domain > ./scripts/install

sed -e "$pattern" ./scripts/version.template > ./scripts/version
