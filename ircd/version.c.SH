#!/bin/sh

set -eu

echo "Extracting comet/ircd/version.c..."

# Generate CREDITS content
credits=$(sed 's/^$/ /;s/.*/    "&",/' ../CREDITS)

# Read template and substitute
sed -e "/@CREDITS@/r /dev/stdin" \
    -e "/@CREDITS@/d" \
    version.c.in > version.c << EOF
$credits
EOF
