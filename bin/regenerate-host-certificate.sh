#!/bin/bash
#
# The purpose of this script is to re-generate the
# host specific server certificate in a test deployment.
#
# Unlike the other scripts, this is supposed to work
# in the staged/installed directory only.

set -e
tempdir="$PWD/$$.tmp"
trap "rm -rf $tempdir" EXIT
mkdir -p $tempdir

if [ -n "$1" -a -d "$1/trusted-ca" ]; then
    export TARGETDIR=$(cd $1; echo $PWD)
else
    if [ -d "$(dirname $0)/../trusted-ca" ]; then
        TARGETDIR=$(cd $(dirname $0)/..; echo $PWD)
    else
        echo "Could not find the 'trusted-ca' directory!" >&2
        exit
    fi
fi
export CA_DIR=$TARGETDIR/trusted-ca

# variables to be used by OpenSSL directly
export CATYPE=trusted
export CN=$(hostname --fqdn)
export BITS=1024
export PASSWORD='changeit'

filebase="$tempdir/server"
echo "Re-generating server certificate for '$CN'"
CMD="openssl req -out $filebase.req -newkey rsa:$BITS -new -keyout $filebase.priv -config $CA_DIR/req_conf.cnf"
[ -n "$VERBOSE" ] && echo $CMD 
$CMD
CMD="openssl ca -in $filebase.req -out $filebase.cert -outdir $tempdir -md md5 -config $CA_DIR/ca_conf.cnf -batch -extensions ca_server -days 1000"
[ -n "$VERBOSE" ] && echo $CMD 
$CMD

cp $filebase.cert $TARGETDIR/grid-security/hostcert.pem
openssl rsa -passin pass:$PASSWORD -in $filebase.priv -out $TARGETDIR/grid-security/hostkey.pem

