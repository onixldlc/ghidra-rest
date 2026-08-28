#!/bin/sh
set -eu

# The server probes itself. The image ships no curl on purpose: pulling curl in
# meant an apt layer, and the apt lists alone were 53 MB of image for one HTTP
# GET that the binary can already do.
exec /usr/local/bin/ghidrarest -healthcheck
