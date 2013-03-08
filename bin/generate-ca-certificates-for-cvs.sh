#!/bin/bash

#
# Copyright (c) Members of the EGEE Collaboration. 2004.
# See http://public.eu-egee.org/partners/ for details on 
# the copyright holders.
# For license conditions see the license file or
# http://eu-egee.org/license.html
#
# Authors: 
#      Joni Hahkala <Joni.Hahlaka@cern.ch>
#      Akos Frohner <Akos.Frohner@cern.ch>
#


CONFIGDIR=$PWD/$(dirname $0)/../config
BASEDIR=$PWD/$(dirname $0)/../test
CONFIGFILES="index.txt serial.txt"
PASSWORD='changeit'
CATYPES='trusted bad fake big expired nokeyusage root subca subsubca slash'
#CATYPES='slash'
BIG_BITS=8192
SMALL_BITS=1024
export DNS_HOSTNAME=DNS:$HOSTNAME

function create_ca {
    catype=$1
    echo "+-----------------------"
    echo "| $catype"
    echo "+-----------------------"
    cadir=${catype}-ca
    if [ ! -f ${cadir}/serial.txt ]; then
        mkdir -p ${cadir}
        cd ${cadir}
        for config in ${CONFIGFILES}; do
            cp $CONFIGDIR/$config .
        done

	sed "s/\$ENV::CATYPE/${catype}/" <$CONFIGDIR/req_conf.cnf > req_conf.cnf

        if [ "$catype" = "big" ]; then
            BITS=$BIG_BITS
        else
            BITS=$SMALL_BITS
        fi

        if [ "$catype" = "expired" ]; then
            DAYS='-days -1'
        else
            DAYS='-days 5000'
        fi

        export CN="the $catype CA"
	if [ "$catype" = "subca" ]; then
	    generate_ca_cert "$catype" root "${DAYS}" false $BITS
		rm ../root/*{.pem,.old,.attr} &>/dev/null
	else
	    if [ "$catype" = "subsubca" ]; then
		generate_ca_cert "$catype" subca "${DAYS}" false $BITS
		rm ../subca/*{.pem,.old,.attr} &>/dev/null
	    else
		generate_ca_cert "$catype" $catype "${DAYS}" true $BITS
	    fi
	fi

    # generating a signing_policy file
	subject_name=`openssl x509 -in ${catype}.cert -subject -noout| sed 's/^subject= //'`
	cat <<EOF > ${catype}.signing_policy
# Signing policy file for the $subject_name"
access_id_CA            X509    '${subject_name}'
pos_rights              globus  CA:sign
cond_subjects           globus  '"$(echo "${subject_name}" | sed -e 's#/CN=.*$##' | sed 's/http:\/\/slash.slash.edu:7656\/testing/Utopia/')/*"'
EOF

        cat <<EOF > ${catype}.namespaces
# Namespace for the $subject_name"
TO Issuer "${subject_name}" \
  PERMIT Subject "$(echo "${subject_name}" | sed -e 's#/CN=.*$##' | sed 's/http:\/\/slash.slash.edu:7656\/testing/Utopia/')/.*"
 
EOF

        if [ "$catype" = "slash" ]; then
	    cat <<EOF >> ${catype}.signing_policy

# add also the namespace with slashes
access_id_CA            X509    '${subject_name}'
pos_rights              globus  CA:sign
cond_subjects           globus  '"$(echo "${subject_name}" | sed -e 's#/CN=.*$##')/*"'

EOF
            cat <<EOF >> ${catype}.namespaces

# add also the namespace with slashes
TO Issuer "${subject_name}" \
  PERMIT Subject "$(echo "${subject_name}" | sed -e 's#/CN=.*$##')/.*"
 
EOF
        fi

        echo -n "Generated CA certificate with "
        openssl x509 -noout -subject -in ${catype}.cert
    else
        echo "${cadir}/serial.txt exists! CA generation for CA ${cadir} skipped."
    fi
    rm *.pem *.old *.attr &>/dev/null
}

function generate_ca_cert {
    catype=$1         # current CA to generate
    parenttype=$2  # parent CA if applicable
    DAYS=$3           # days flag
    selfsign=$4       # whether to generate self signed CA or hierarchical
    bits=$5           # number of bits for the CA cert
    export CASROOT=../
    
    echo `pwd`

    if [ "$catype" = "slash" ]; then
	dn="/C=UG/L=Tropic/O=http:\/\/slash.slash.edu:7656\/testing/OU=Relaxation/CN=the ${catype} CA"
    else
	dn="/C=UG/L=Tropic/O=Utopia/OU=Relaxation/CN=the ${catype} CA"
    fi

    echo $dn

    if [ x$selfsign == "xfalse" ]; then
	openssl req -new -out ${catype}.req ${DAYS} -nodes -keyout ${catype}.priv \
	    -config req_conf.cnf -newkey rsa:$bits -subj "$dn"
	if [ $? -ne "0" ]; then
	    echo CA certificate request generation failed!
	    exit 1
	fi
	echo `pwd`
	openssl ca -in ${catype}.req -out ${catype}.cert -outdir . \
	    -md md5 -cert $CASROOT/$parenttype-ca/$parenttype.cert -keyfile $CASROOT/$parenttype-ca/$parenttype.priv \
	    -config req_conf.cnf -batch -extensions ca_cert_req ${DAYS}
	if [ $? -ne "0" ]; then
	    echo CA certificate signing failed!
	    exit 1
	fi
    else
	if [ x$catype == "xnokeyusage" ]; then
	    openssl req -new -x509 -out ${catype}.cert $DAYS -nodes \
		-keyout ${catype}.priv -config req_conf.cnf -newkey rsa:$bits -extensions ca_cert_req_nokeyusage -subj "${dn}"
	    if [ $? -ne "0" ]; then
		echo CA certificate generation failed!
		exit 1
	    fi
	else
	    openssl req -new -x509 -out ${catype}.cert $DAYS -nodes  \
		-keyout ${catype}.priv -config req_conf.cnf -newkey rsa:$bits -extensions ca_cert_req -subj "${dn}"
	    if [ $? -ne "0" ]; then
		echo CA certificate generation failed!
		exit 1
	    fi
	fi
    fi

    openssl pkcs12 -export -in ${catype}.cert -inkey ${catype}.priv \
	-out ${catype}.p12 -passin "pass:$PASSWORD" -passout "pass:$PASSWORD"
    if [ $? -ne "0" ]; then
	echo CA certificate packing into pkcs12 keystore failed!
	exit 1
    fi
}

############################## main ################################

if [ "$1" != "--i-know-what-i-am-doing" ]; then
    echo "Please read the README file before executing this command!"
    exit -1
fi

mkdir -p $BASEDIR
cd $BASEDIR
ABSBASEDIR=$(pwd)

for catype in $CATYPES; do
    create_ca $catype
    cd $ABSBASEDIR
done
