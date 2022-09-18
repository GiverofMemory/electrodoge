#!/bin/bash

set -e

APPDIR="$(dirname "$(readlink -e "$0")")"

export LD_LIBRARY_PATH="${APPDIR}/usr/lib/:${APPDIR}/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH+:$LD_LIBRARY_PATH}"
export PATH="${APPDIR}/usr/bin:${PATH}"
export LDFLAGS="-L${APPDIR}/usr/lib/x86_64-linux-gnu -L${APPDIR}/usr/lib"
<<<<<<< HEAD
exec "${APPDIR}/usr/bin/python3" -s "${APPDIR}/usr/bin/electrodoge" "$@"
=======

exec "${APPDIR}/usr/bin/python3" -s "${APPDIR}/usr/bin/electrodoge" "$@"
>>>>>>> 6354f30a876b12c17f8b5576fa559d672232521d
