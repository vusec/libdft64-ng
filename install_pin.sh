#!/bin/bash
set -eux
PREFIX=${PREFIX:-${HOME}}

TAR_NAME="pin-3.24-98612-g6bd5931f2-gcc-linux"

wget https://software.intel.com/sites/landingpage/pintool/downloads/${TAR_NAME}.tar.gz
tar -C "${PREFIX}" -xzf ${TAR_NAME}.tar.gz
rm ${TAR_NAME}.tar.gz

set +x
echo "Please set:"
echo "export PIN_ROOT=\"${PREFIX}/${TAR_NAME}\""
