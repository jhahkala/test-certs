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
#      John White   <John.White@cern.ch>
#


# generating the PKCS#12 format
function create_p12 {
    name=$1
    echo "Generating PKCS#12 format for $name.(cert|priv)"
    openssl pkcs12 -in $name.cert -out $name.p12 -export -inkey $name.priv \
        -passin pass:$PASSWORD -passout pass:$PASSWORD
}

function create_cert {
    filebase=$1
    flags=$3
    validity=$4
    bits=${5:-1024}

    dn="/C=UG/L=Tropic/O=Utopia/OU=Relaxation/CN=$2"

    md=sha1

    echo "Creating a cert for '$2' in files named $filebase.(cert|priv)"
    echo "                with $flags flags and $validity days validity time"

    if [ -r "$filebase.cert" -o -r "$filebase.priv" ]; then
        echo "There already exists a file named $filebase.cert or $filebase.priv"
        echo "file. Certificate is not generated for '$CN'"
        return 
    fi

    castring=""

    # if we are in a state where we are generating proxies (${CA_DIR}/serial_proxy.txt exists)
    # then let's transfer the serial number of the last proxy to the serial.txt file for the 
    # next new certificate...
    CMD="openssl req -out $filebase.req -newkey rsa:$bits -new -keyout $filebase.priv -config $REQ_CONFIG_FILE -passout pass:$PASSWORD"

    # mangle the DN and revert flag to normal client to handle it as normal client otherwise suring certificate req generation.
    case $flags in
        clientserial)
	    echo serial cert $flags
	    flags="client"
	    CMD="$CMD -subj \"$dn/serialNumber=12341\""
            ;;
        clientemail)
	    echo email cert $flags
	    flags="client"
	    CMD="$CMD -subj \"$dn/emailAddress=john.doe@foo.bar\""
            ;;
        clientuid)
	    echo UID cert $flags
	    flags="client"
	    CMD="$CMD -subj \"$dn/UID=haahaa\""
            ;;
	clientbaddn)
	    echo bad DN cert $flags
	    flags="client"
	    CMD="$CMD -subj \"`echo $dn | sed 's/Relaxation/Chilling/'`\""
	    ;;
	hostbaddn)
	    echo bad DN host cert $flags
	    flags="server"
	    CMD="$CMD -subj \"`echo $dn | sed 's/Relaxation/Chilling/'`\""
	    ;;
	hostemail)
	    echo email DN cert $flags
	    flags="server"
	    CMD="$CMD -subj \"$dn/emailAddress=john.doe@foo.bar\""
	    ;;
	clientfuture)
	    echo future user cert $flags
	    flags="client"
	    CMD="$CMD -subj \"$dn\""
	    castring=" -startdate 350101000000Z"
	    ;;
	client_slash)
	    echo user cert with slash and dots in DN$flags
	    flags="client"
	    CMD="$CMD -subj \"$(echo $dn | sed 's/Utopia/http:\\\/\\\/slash.slash.edu:7656\\\/testing/')\""
	    ;;
        *)
	    echo normal cert $flags
	    CMD="$CMD -subj \"$dn\""
    esac
    
    echo $CMD;eval $CMD;
    if [ $? != 0 ]; then
	echo Certification request generation failed!
	exit 1
    fi

    # the different has function options, set the md value end revert to normal client cert signing
    case $flags in
        clientmd5)
	    echo user cert with MD5 hash $flags
	    flags="client"
	    md="md5"
	    ;;
        clientsha224)
	    echo user cert with sha224 hash $flags
	    flags="client"
	    md="sha224"
	    ;;
        clientsha256)
	    echo user cert with sha256 hash $flags
	    flags="client"
	    md="sha256"
	    ;;
        clientsha384)
	    echo user cert with sha384 hash $flags
	    flags="client"
	    md="sha384"
	    ;;
        clientsha512)
	    echo user cert with sha512 hash $flags
	    flags="client"
	    md="sha512"
	    ;;
    esac

    case $flags in
        client|server|clientserver|fclient|none|altname|altname2|altname3)
            echo "Generating a $flags certificate"
            echo $CA_DIR
	    echo PDW=`pwd`
            CMD="openssl ca -in $filebase.req -out $filebase.cert -outdir $tmpdir \
                         -md $md -config $REQ_CONFIG_FILE -batch -preserveDN \
                         -extensions ca_$flags -passin pass:$PASSWORD -days $validity $castring"
            ;;
        *)
            echo "Unknown flags: $flags"
            echo "No certificate is generated."
	    exit 1
    esac

    # save the index and serial for the possible proxy to be generated next
    echo save the index and serial
    cp $CA_DIR/index.txt $CA_DIR/index_proxy.txt
    cp $CA_DIR/serial.txt $CA_DIR/serial_proxy.txt

    echo $CMD; eval $CMD
    if [ $? != 0 ]; then
	echo Certificate signing failed!
	exit 1
    fi

    create_p12 $filebase
}

# create_cert_proxy "file base (signer)" "ignored" "added part to filename" "CN part to add" "days"
function create_cert_proxy {

    filebase=$1
    ident=$3
    validity=$5

    ending="grid_proxy"

    echo "##### creating proxy $1.$3.$ending"

    # This really depends on if we make a proxy or a proxy-proxy
    X509_SIGNING_CERT=${filebase}.cert
    X509_SIGNING_KEY=${filebase}.priv

    X509_PROX_CERT=${filebase}.${ident}.cert
    X509_PROX_KEY=${filebase}.${ident}.priv
    X509_PROX_REQ=${filebase}.${ident}.req
    X509_PROX_GRID=${filebase}.${ident}.${ending}

    if [ x$ident == "xproxy_dnerror2" ]; then
	dn="`openssl x509 -in ${X509_SIGNING_CERT} -subject -noout| sed 's/^subject= //'` dnerror2/CN=$4"
    else
	dn="$(openssl x509 -in ${X509_SIGNING_CERT} -subject -noout| sed 's/^subject= //' |sed 's/http:\/\/slash.slash.edu:7656\/testing/http:\\\/\\\/slash.slash.edu:7656\\\/testing/')/CN=$4"
    fi
 
    echo "Creating a proxy cert ${X509_PROX_CERT} for '$dn"
    echo "         in files named $filebase.(cert|priv)"
    echo "         with $validity days validity time"

    if [ -r "${X509_PROX_CERT}" ]; then
        echo "There already exists a file named ${X509_PROX_CERT}"
        echo "file. Proxy certificate is not generated for '$dn'"
        return 
    fi

    # instead save the ones for real certs and copy the ones saved before and use them and later switch back
    cp ${CA_DIR}/index.txt ${CA_DIR}/index_cert_save.txt
    cp ${CA_DIR}/serial.txt ${CA_DIR}/serial_cert_save.txt
    cp ${CA_DIR}/index_proxy.txt ${CA_DIR}/index.txt 
    cp ${CA_DIR}/serial_proxy.txt ${CA_DIR}/serial.txt 
    
    CMD="openssl genrsa -f4 -out ${X509_PROX_KEY} ${PROXY_BITS}; chmod 400 ${filebase}.proxy.priv"
    echo $CMD; $CMD
    if [ $? != 0 ]; then
	echo Private key generation for proxy failed!
	exit 1
    fi

    # Create the certificate request.
    CMD="openssl req -new -out ${X509_PROX_REQ} \
                 -key ${X509_PROX_KEY} \
                 -config ${REQ_CONFIG_FILE} -subj \"$dn\""
    echo $CMD; eval $CMD

    if [ $? != 0 ]; then
	echo Certificate generation for proxy failed!
	exit 1
    fi

    # Sign the cert request with the user cert and key. Set the serial number here!
    CMD="openssl ca -verbose -in ${X509_PROX_REQ} \
                    -cert ${X509_SIGNING_CERT} \
                    -keyfile ${X509_SIGNING_KEY} \
                    -out ${X509_PROX_CERT} \
                    -outdir $tmpdir \
                    -preserveDN \
                    -config ${REQ_CONFIG_FILE} -md md5 -days ${validity} -batch \
                    -passin pass:${PASSWORD} -notext"
    
    case $ident in
	proxy_rfc)
	    CMD="$CMD -extensions proxy_rfc"
	    ;;
	proxy_rfc_anyp)
	    CMD="$CMD -extensions proxy_rfc_anypolicy"
	    ;;
	proxy_rfc_indep)
	    CMD="$CMD -extensions proxy_rfc_independent"
	    ;;
	proxy_rfc_lim)
	    CMD="$CMD -extensions proxy_rfc_limited"
	    ;;
	proxy_rfc_plen)
	    CMD="$CMD -extensions proxy_rfc_pathLen1"
	    ;;
	proxy_invKeyusage)
	    CMD="$CMD -extensions proxy_invalid_usage"
	    ;;
    esac
    echo $CMD; $CMD

    if [ $? != 0 ]; then
	echo Proxy certificate signing failed!
	exit 1
    fi

    # Add the user and proxy certs and the proxy private key to the keystore
    CMD="openssl pkcs12 -in ${X509_PROX_CERT} \
                   -out ${filebase}.proxy.p12 -export \
                   -inkey ${X509_PROX_KEY} \
                   -passin pass:${PASSWORD} -passout pass:${PASSWORD} \
                   -name \"${catype} proxy certificate\" -certfile ${filebase}.cert"

    echo $CMD; eval $CMD

    # Create a grid proxy file... 
    # Copy the proxy cert to the grid proxy file.
    cp ${X509_PROX_CERT} ${X509_PROX_GRID}
    
    if [ $? != 0 ]; then
	echo Proxy file generation failed!
	exit 1
    fi

    # Now add the proxy private key to the grid proxy file.
    openssl rsa -in ${X509_PROX_KEY} -passin pass:${PASSWORD} >> ${X509_PROX_GRID}
    
    if [ $? != 0 ]; then
	echo Proxy file generation failed!
	exit 1
    fi

    # Now add the original certificate used to sign the request to the proxy file.
    # This should be the certificate issued by the CA to the 'user'.
    CMD="openssl x509 -in ${X509_SIGNING_CERT} >> ${X509_PROX_GRID}"
    echo $CMD; eval "$CMD"

    if [ $? != 0 ]; then
	echo Proxy file generation failed!
	exit 1
    fi

    chmod 600 ${X509_PROX_GRID}

    # copy the normal cert files back
    cp ${CA_DIR}/index_cert_save.txt ${CA_DIR}/index.txt
    cp ${CA_DIR}/serial_cert_save.txt ${CA_DIR}/serial.txt
}


# create_cert_proxy "file base (signer)" "ignored" "added part to filename" "CN part to add" "days"
# create_cert_proxy_proxy "file base (signer)" "ignored" "added part to filename" "CN part to add" "days" "first proxy type"
function create_cert_proxy_proxy {

    ending="grid_proxy"

    echo "############## creating proxy-proxy $1.$6.$3.$ending"

    create_cert_proxy $1.$6 "$2" $3 "$4" $5
 
    # adding in the original certificate to the chain. 03/06/05
    CMD="openssl x509 -in $1.cert >> \"$1.$6.$3.$ending\""
    echo "$CMD"; eval "$CMD"

    if [ $? != 0 ]; then
	echo Proxy file generation failed!
	exit 1
    fi
}

# create_cert_proxy             "file base (signer)" "ignored" "added part to filename" "CN part to add" "days"
# create_cert_proxy_proxy       "file base (signer)" "ignored" "added part to filename" "CN part to add" "days" "first proxy type"
# create_cert_proxy_proxy_proxy "file base (signer)" "ignored" "added part to filename" "CN part to add" "days" "first proxy type" "second proxy type"
function create_cert_proxy_proxy_proxy {

    ending="grid_proxy"

    echo "############################  creating proxy-proxy-proxy $1.$6.$7.$3.$ending"

    create_cert_proxy_proxy $1.$6 "$2" $3 "$4" $5 $7
 
#    echo Appending $1.cert to "$1.$3.$6.$ending"
    # adding in the original certificate to the chain. 03/06/05
    CMD="openssl x509 -in $1.cert >> \"$1.$6.$7.$3.$ending\""
    echo "$CMD"; eval "$CMD"

    if [ $? != 0 ]; then
	echo Proxy file generation failed!
	exit 1
    fi
}

function create_voms {
    filename=$1
    shift
    
    usercert='home/usercert.pem'
    userkey='home/userkey.pem'
    if [ "$1" = '-cert' ]; then
        shift
        usercert="$1"
        shift
    fi
    if [ "$1" = '-key' ]; then
        shift
        userkey="$1"
        shift
    fi

    # checking then environment
    if [ ! -r "$usercert" -o ! -r "$userkey" ]; then
        echo "Error: cannot read '$usercert' or '$userkey'" >&2
        return
    fi
    if [ ! -r 'grid-security/hostcert.pem' -o ! -r 'grid-security/hostkey.pem' ]; then
        echo "Error: cannot read 'grid-security/hostcert.pem' or 'grid-security/hostkey.pem'" >&2
        return
    fi

    # making sure X509_VOMS_DIR exists
    if [ ! -d 'grid-security/vomsdir' ]; then
        mkdir -p 'grid-security/vomsdir'
    fi
    if [ ! -f 'grid-security/vomsdir/hostcert.pem' ]; then
        cp grid-security/hostcert.pem grid-security/vomsdir/
    fi
    export X509_VOMS_DIR='grid-security/vomsdir'

    # using user credentials for both due to #17362
    # https://savannah.cern.ch/bugs/index.php?func=detailitem&item_id=17362
    cp $usercert grid-security/vomsdir/
    CMD="openssl rsa -in $userkey -out $userkey-nopwd -passin pass:$PASSWORD"
    echo $CMD
    $CMD
    CMD="chmod 600 $userkey-nopwd"
    $CMD

    vo=${1:1}
    CMD="voms-proxy-fake -pwstdin -hours 168 -newformat \
                    -cert $usercert -key $userkey-nopwd \
                    -certdir grid-security/certificates/ \
                    -hostcert $usercert -hostkey $userkey-nopwd \
                    -out $filename -voms $vo \
                    "$(for fqan in $@; do echo -n "-fqan $fqan "; done)
    echo $CMD
    $CMD

    CMD="rm $userkey-nopwd"
    $CMD
}  

# create some certificates and copy them to convenient locations
function create_some {

    # generating client certificate
    create_cert $CERT_DIR/${catype}_client00 "$LOGNAME" client $DAYS

    # generate extra client certificates
    if [ -n "$EXTRACERTS" ]; then
        echo "Generating '$EXTRACERTS' extra certs"
        extra_ids=$(seq -f '%02g' 1 $EXTRACERTS)
        if [ "$VOMS" = 'yes' ]; then
            # 'wv' stands for Wrong Voms certificate
            extra_ids="$extra_ids wv"
        fi
        for i in $extra_ids; do
            create_cert $CERT_DIR/${catype}_client$i "$LOGNAME client$i" client $DAYS
        done
    fi
    
    # generating host certificate
    create_cert $CERT_DIR/${catype}_host $hostname_full server $DAYS

    # generating CRL
    openssl ca -gencrl -crldays 5000 -out $CA_DIR/${catype}.crl -config $REQ_CONFIG_FILE

    add_ca_grid_sec ${catype}

    cp $CERT_DIR/${catype}_host.cert grid-security/hostcert.pem
    openssl rsa -passin pass:$PASSWORD -in $CERT_DIR/${catype}_host.priv -out grid-security/hostkey.pem
    chmod 400 grid-security/hostkey.pem
    
    if [ ! -d 'home' ]; then
        mkdir 'home'
    fi
    cp -f $CERT_DIR/${catype}_client00.cert home/usercert.pem
    cp -f $CERT_DIR/${catype}_client00.priv home/userkey.pem
    cp -f $CERT_DIR/${catype}_client00.p12 home/user.p12
    # set the correct permissions for globus...
    chmod 400 home/userkey.pem

    # copy extra certificates
    if [ -n "$EXTRACERTS" ]; then
        echo "Copying '$EXTRACERTS' extra certs"
        for i in $extra_ids; do
            cp -f $CERT_DIR/${catype}_client$i.cert home/usercert$i.pem
            cp -f $CERT_DIR/${catype}_client$i.priv home/userkey$i.pem
            # set the correct permissions for globus...
            chmod 400 home/userkey$i.pem
        done
    fi

    # creating some fake VOMS certificates
    if [ "$VOMS" = 'yes' -a -x "$(which voms-proxy-fake)" ]; then
        create_voms home/voms-acme.pem /org.acme
        create_voms home/voms-acme-Radmin.pem /org.acme /org.acme/Role=Admin
        create_voms home/voms-acme-Gproduction.pem /org.acme /org.acme/production
        create_voms home/voms-coyote.pem /org.coyote
        create_voms home/voms-coyote-Radmin.pem /org.coyote /org.coyote/Role=Admin
        create_voms home/voms-coyote-Gproduction.pem /org.coyote /org.coyote/production

        # and some basics for the extra certs
        if [ -n "$EXTRACERTS" ]; then
            echo "Generating '$EXTRACERTS' vomsified extra certs"
            for i in $extra_ids; do
                create_voms home/voms$i-acme.pem \
                    -cert home/usercert$i.pem -key home/userkey$i.pem \
                    /org.acme
            done
            
            # There is an extra certificate, with supposed to be wrong
            # VOMS attributes: we need to remove the issuer certificate
            # from vomsdir to make it happen.
            rm grid-security/vomsdir/usercertwv.pem
        fi
    fi

    if [ -r "$CONFIGDIR/../bin/regenerate-host-certificate.sh" ]; then
        echo "Copying the host-cert re-generation special tool..."
        if [ ! -d 'bin' ]; then
            mkdir bin
        fi
        cp -u $CONFIGDIR/../bin/regenerate-host-certificate.sh bin/
    fi
}

# add a ca to the grid-security/certificates directory
function add_ca_grid_sec {

    if [ ! -d 'grid-security/certificates' ]; then
        mkdir -p 'grid-security/certificates'
    fi
    if [ ! -d 'grid-security/certificates-withoutCrl' ]; then
        mkdir -p 'grid-security/certificates-withoutCrl'
    fi
    if [ ! -d 'grid-security/certificates-rootwithpolicy' ]; then
        mkdir -p 'grid-security/certificates-rootwithpolicy'
    fi
    if [ ! -d 'grid-security/certificates-rootallowsubsubdeny' ]; then
        mkdir -p 'grid-security/certificates-rootallowsubsubdeny'
    fi
    if [ ! -d 'grid-security/certificates-subcawithpolicy' ]; then
        mkdir -p 'grid-security/certificates-subcawithpolicy'
    fi
    if [ ! -d 'grid-security/certificates-withoutroot' ]; then
        mkdir -p 'grid-security/certificates-withoutroot'
    fi
    if [ ! -d 'grid-security/certificates-withnamespaceerrors' ]; then
        mkdir -p 'grid-security/certificates-withnamespaceerrors'
    fi
    if [ ! -d 'grid-security/certificates-slashwithoutnamespaces' ]; then
        mkdir -p 'grid-security/certificates-slashwithoutnamespaces'
    fi
    if [ x"`openssl version`" \< x"OpenSSL 1.0.0" ]; then
        hash=$(openssl x509 -subject_hash -noout -in $1-ca/$1.cert)
    else
	echo new openssl
        hash=$(openssl x509 -subject_hash_old -noout -in $1-ca/$1.cert)
	hash2=$(openssl x509 -subject_hash -noout -in $1-ca/$1.cert)    
	echo old hash $hash
	echo new hash $hash2
    fi
    cp $1-ca/$1.cert grid-security/certificates/${hash}.0
    cp $1-ca/$1.crl grid-security/certificates/${hash}.r0
    # generating a signing_policy file
    subject_name=$(openssl x509 -in $1-ca/$1.cert -subject -noout)
    cat <<EOF >grid-security/certificates/${hash}.signing_policy
# Signing policy file for the $(echo "$subject_name" | sed -e 's#^.*/CN=##')
access_id_CA            X509    '${subject_name:9}'
pos_rights              globus  CA:sign
cond_subjects           globus  '"$(echo "${subject_name:9}" | sed -e 's#/CN=.*$##')/*"'
EOF
    cat <<EOF >grid-security/certificates/${hash}.namespaces
##############################################################################
#NAMESPACES-VERSION: 1.0
# Namespaces file for the $(echo "$subject_name" | sed -e 's#^.*/CN=##')
TO Issuer "${subject_name:9}" \
  PERMIT Subject "$(echo "${subject_name:9}" | sed -e 's#/CN=.*$##')/.*"
EOF
    cp grid-security/certificates/${hash}.* grid-security/certificates-rootwithpolicy
    cp grid-security/certificates/${hash}.* grid-security/certificates-rootallowsubsubdeny
    cp grid-security/certificates/${hash}.* grid-security/certificates-subcawithpolicy
    cp grid-security/certificates/${hash}.* grid-security/certificates-withnamespaceerrors
    cp grid-security/certificates/${hash}.* grid-security/certificates-withoutroot
    cp grid-security/certificates/${hash}.* grid-security/certificates-slashwithoutnamespaces

    if [ "$1" = 'slash' ]; then
        rm grid-security/certificates-slashwithoutnamespaces/${hash}.namespaces
    fi

#override root and sub namespaces
    if [ "$1" = 'root' ]; then
	cat <<EOF >grid-security/certificates/${hash}.namespaces
##############################################################################
#NAMESPACES-VERSION: 1.0
# Namespaces file for the $(echo "$subject_name" | sed -e 's#^.*/CN=##')
TO Issuer "${subject_name:9}" \
  PERMIT Subject "/C=UG/L=Tropic/O=Utopia/OU=Relaxation/CN=the subca CA"
EOF
	cat <<EOF >grid-security/certificates/${hash}.signing_policy
# Signing policy file for the $(echo "$subject_name" | sed -e 's#^.*/CN=##')
access_id_CA            X509    '${subject_name:9}'
pos_rights              globus  CA:sign
cond_subjects           globus  '"/C=UG/L=Tropic/O=Utopia/OU=Relaxation/CN=the subca CA"'
EOF
	cat <<EOF >grid-security/certificates-rootwithpolicy/${hash}.namespaces
##############################################################################
#NAMESPACES-VERSION: 1.0
# Namespaces file for the $(echo "$subject_name" | sed -e 's#^.*/CN=##')
TO Issuer "${subject_name:9}" \
  PERMIT Subject "/C=UG/L=Tropic/O=Utopia/OU=Relaxation/CN=the subca CA"
TO Issuer "/C=UG/L=Tropic/O=Utopia/OU=Relaxation/CN=the subca CA" \
  PERMIT Subject "/C=UG/L=Tropic/O=Utopia/OU=Relaxation/CN=the subsubca CA"
TO Issuer "/C=UG/L=Tropic/O=Utopia/OU=Relaxation/CN=the subsubca CA" \
  PERMIT Subject "/C=UG/L=Tropic/O=Utopia/OU=Relaxation/CN=.*"
EOF
	cat <<EOF >grid-security/certificates-rootwithpolicy/${hash}.signing_policy
# Signing policy file for the $(echo "$subject_name" | sed -e 's#^.*/CN=##')
access_id_CA            X509    '${subject_name:9}'
pos_rights              globus  CA:sign
cond_subjects           globus  '"/C=UG/L=Tropic/O=Utopia/OU=Relaxation/CN=the subca CA"'
access_id_CA            X509    '/C=UG/L=Tropic/O=Utopia/OU=Relaxation/CN=the subca CA'
pos_rights              globus  CA:sign
cond_subjects           globus  '"/C=UG/L=Tropic/O=Utopia/OU=Relaxation/CN=the subsubca CA"'
access_id_CA            X509    '/C=UG/L=Tropic/O=Utopia/OU=Relaxation/CN=the subsubca CA'
pos_rights              globus  CA:sign
cond_subjects           globus  '"/C=UG/L=Tropic/O=Utopia/OU=Relaxation/CN=*"'
EOF
	cat <<EOF >grid-security/certificates-rootallowsubsubdeny/${hash}.namespaces
##############################################################################
#NAMESPACES-VERSION: 1.0
# Namespaces file for the $(echo "$subject_name" | sed -e 's#^.*/CN=##')
TO Issuer "${subject_name:9}" \
  PERMIT Subject "/C=UG/L=Tropic/O=Utopia/OU=Relaxation/CN=the subca CA"
TO Issuer "/C=UG/L=Tropic/O=Utopia/OU=Relaxation/CN=the subca CA" \
  PERMIT Subject "/C=UG/L=Tropic/O=Utopia/OU=Relaxation/CN=the subsubca CA"
TO Issuer "/C=UG/L=Tropic/O=Utopia/OU=Relaxation/CN=the subsubca CA" \
  PERMIT Subject "/C=UG/L=Tropic/O=Utopia/OU=Relaxation/CN=.*"
EOF
	cat <<EOF >grid-security/certificates-rootallowsubsubdeny/${hash}.signing_policy
# Signing policy file for the $(echo "$subject_name" | sed -e 's#^.*/CN=##')
access_id_CA            X509    '${subject_name:9}'
pos_rights              globus  CA:sign
cond_subjects           globus  '"/C=UG/L=Tropic/O=Utopia/OU=Relaxation/CN=the subca CA*"'
access_id_CA            X509    '/C=UG/L=Tropic/O=Utopia/OU=Relaxation/CN=the subca CA'
pos_rights              globus  CA:sign
cond_subjects           globus  '"/C=UG/L=Tropic/O=Utopia/OU=Relaxation/CN=the subsubca CA"'
access_id_CA            X509    '/C=UG/L=Tropic/O=Utopia/OU=Relaxation/CN=the subsubca CA'
pos_rights              globus  CA:sign
cond_subjects           globus  '"/C=UG/L=Tropic/O=Utopia/OU=Relaxation/CN=*"'
EOF
	rm grid-security/certificates-subcawithpolicy/${hash}.{namespaces,signing_policy}
	rm grid-security/certificates-withoutroot/${hash}.*
    fi
    if [ "$1" = 'subca' ]; then
	cat <<EOF >grid-security/certificates/${hash}.namespaces
##############################################################################
#NAMESPACES-VERSION: 1.0
# Namespaces file for the $(echo "$subject_name" | sed -e 's#^.*/CN=##')
TO Issuer "${subject_name:9}" \
  PERMIT Subject "/C=UG/L=Tropic/O=Utopia/OU=Relaxation/CN=the subsubca CA"
EOF
	cat <<EOF >grid-security/certificates/${hash}.signing_policy
# Signing policy file for the $(echo "$subject_name" | sed -e 's#^.*/CN=##')
access_id_CA            X509    '${subject_name:9}'
pos_rights              globus  CA:sign
cond_subjects           globus  '"/C=UG/L=Tropic/O=Utopia/OU=Relaxation/CN=the subsubca CA"'
EOF
	rm grid-security/certificates-rootwithpolicy/${hash}.{namespaces,signing_policy}
	cat <<EOF >grid-security/certificates-rootallowsubsubdeny/${hash}.namespaces
##############################################################################
#NAMESPACES-VERSION: 1.0
# Namespaces file for the $(echo "$subject_name" | sed -e 's#^.*/CN=##')
TO Issuer "${subject_name:9}" \
  PERMIT Subject "/C=UG/L=Tropic/O=Utopia/OU=Relaxation/CN=the subsubca CA"
EOF
	rm grid-security/certificates-rootallowsubsubdeny/${hash}.{signing_policy,namespaces}
	cat <<EOF >grid-security/certificates-subcawithpolicy/${hash}.namespaces
##############################################################################
#NAMESPACES-VERSION: 1.0
# Namespaces file for the $(echo "$subject_name" | sed -e 's#^.*/CN=##')
TO Issuer "${subject_name:9}" \
  PERMIT Subject "/C=UG/L=Tropic/O=Utopia/OU=Relaxation/CN=the subsubca CA"
TO Issuer "/C=UG/L=Tropic/O=Utopia/OU=Relaxation/CN=the subsubca CA" \
  PERMIT Subject "/C=UG/L=Tropic/O=Utopia/OU=Relaxation/CN=.*"
EOF
	cat <<EOF >grid-security/certificates-subcawithpolicy/${hash}.signing_policy
# Signing policy file for the $(echo "$subject_name" | sed -e 's#^.*/CN=##')
access_id_CA            X509    '${subject_name:9}'
pos_rights              globus  CA:sign
cond_subjects           globus  '"/C=UG/L=Tropic/O=Utopia/OU=Relaxation/CN=the subsubca CA"'
access_id_CA            X509    '/C=UG/L=Tropic/O=Utopia/OU=Relaxation/CN=the subsubca CA'
pos_rights              globus  CA:sign
cond_subjects           globus  '"/C=UG/L=Tropic/O=Utopia/OU=Relaxation/CN=*"'
EOF
	cat <<EOF >grid-security/certificates-withnamespaceerrors/${hash}.namespaces
##############################################################################
#NAMESPACES-VERSION: 1.0
# Namespaces file for the $(echo "$subject_name" | sed -e 's#^.*/CN=##')
TO Isser "${subject_name:9}" \
  PERMIT Subject "/C=UG/L=Tropic/O=Utopia/OU=Relaxation/CN=the subca CA"
EOF
	cat <<EOF >grid-security/certificates-withnamespaceerrors/${hash}.signing_policy
# Signing policy file for the $(echo "$subject_name" | sed -e 's#^.*/CN=##')
access_id_CA             '${subject_name:9}'
pos_rights              globus  CA:sign
cond_subjects           globus  '"/C=UG/L=Tropic/O=Utopia/OU=Relaxation/CN=the subca CA"'
EOF
    fi
    if [ "$1" = 'subsubca' ]; then
	cat <<EOF >grid-security/certificates/${hash}.namespaces
##############################################################################
#NAMESPACES-VERSION: 1.0
# Namespaces file for the $(echo "$subject_name" | sed -e 's#^.*/CN=##')
TO Issuer "${subject_name:9}" \
  PERMIT Subject "/C=UG/L=Tropic/O=Utopia/OU=Relaxation/CN=.*"
EOF
	cat <<EOF >grid-security/certificates/${hash}.signing_policy
# Signing policy file for the $(echo "$subject_name" | sed -e 's#^.*/CN=##')
access_id_CA            X509    '${subject_name:9}'
pos_rights              globus  CA:sign
cond_subjects           globus  '"/C=UG/L=Tropic/O=Utopia/OU=Relaxation/CN=*"'
EOF
	rm grid-security/certificates-rootwithpolicy/${hash}.{namespaces,signing_policy}
	cat <<EOF >grid-security/certificates-rootallowsubsubdeny/${hash}.namespaces
##############################################################################
#NAMESPACES-VERSION: 1.0
# Namespaces file for the $(echo "$subject_name" | sed -e 's#^.*/CN=##')
TO Issuer "${subject_name:9}" \
  PERMIT Subject "/C=UG/L=Tropic/O=Utopia-not/OU=Relaxation/CN=.*"
EOF
	cat <<EOF >grid-security/certificates-rootallowsubsubdeny/${hash}.signing_policy
# Signing policy file for the $(echo "$subject_name" | sed -e 's#^.*/CN=##')
access_id_CA            X509    '${subject_name:9}'
pos_rights              globus  CA:sign
cond_subjects           globus  '"/C=UG/L=Tropic/O=Utopia-not/OU=Relaxation/CN=*"'
EOF
        rm grid-security/certificates-subcawithpolicy/${hash}.{namespaces,signing_policy}
    fi

    cp grid-security/certificates/${hash}.* grid-security/certificates-withoutCrl
    rm grid-security/certificates-withoutCrl/*.r0

# copy all certs to their new hash if the openssl is using new hashes
    if [ x${hash2} != "x" ]; then
	for oldCa in `find grid-security -name ${hash}.0`; do
	    echo cp ${oldCa} `dirname ${oldCa}`/${hash2}.0
	    cp ${oldCa} `dirname ${oldCa}`/${hash2}.0
	done
        for oldCa in `find grid-security -name ${hash}.r0`; do
            cp ${oldCa} `dirname ${oldCa}`/${hash2}.r0
        done
        for oldCa in `find grid-security -name ${hash}.signing_policy`; do
            cp ${oldCa} `dirname ${oldCa}`/${hash2}.signing_policy
        done
        for oldCa in `find grid-security -name ${hash}.namespaces`; do
            cp ${oldCa} `dirname ${oldCa}`/${hash2}.namespaces
        done
    fi
	
}

function copy_ca {
    echo copying CA from $1 to $2 current dir $PWD
    # putting the CA certificate to the right place
    if [ ! -d "$1" ]; then
        echo "CA files are not found: $1"
        echo "Did you run 'generate-ca-certificates-for-cvs.sh'?"
        exit -1
    fi
    if [ -d "$2" ]; then
        echo "CA directory already exists: $2"
    else
        CMD="cp -a $1 $2"
	echo $CMD
	$CMD
	
        result=$?
        if [ $result -ne 0 ];then
            echo "The copying of CA from $1 failed with error code $result"
            exit -1
        fi
        # remove the CVS dir, if it was copied...
        if [ -d "$2/CVS" ]; then
            rm -rf "$2/CVS"
        fi
    fi
}

# create all certificates
function create_all {

    # create valid certs with proxies

    PROXY_VALIDITY=5000
	
    TYPE="client"
    CTYPE="client"

    create_cert $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" ${TYPE} $DAYS
    openssl pkcs8 -in $CERT_DIR/${catype}_${TYPE}.priv -topk8 -passin pass:${PASSWORD} -nocrypt >$CERT_DIR/${catype}_${TYPE}.priv.pkcs8
    create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY
    create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_dnerror "dnerror proxy" $PROXY_VALIDITY
    create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_dnerror2 "proxy" $PROXY_VALIDITY
    create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_lim "limited proxy" $PROXY_VALIDITY
    create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_exp "proxy" -1
    create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_rfc "rfc proxy" $PROXY_VALIDITY
    create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_rfc_anyp "rfc any policy proxy" $PROXY_VALIDITY
    create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_rfc_lim "limited rfc proxy" $PROXY_VALIDITY
    create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_rfc_indep "rfc independent proxy" $PROXY_VALIDITY
    create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_rfc_plen "rfc path len 1 proxy" $PROXY_VALIDITY
    create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_invKeyusage "proxy" $PROXY_VALIDITY


    create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY proxy
    create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_dnerror "dnerror proxy" $PROXY_VALIDITY proxy
    create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_lim "limited proxy" $PROXY_VALIDITY proxy

    create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY proxy_dnerror
    create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_dnerror "dnerror proxy" $PROXY_VALIDITY proxy_dnerror
    create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_lim "limited proxy" $PROXY_VALIDITY proxy_dnerror

    create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY proxy_lim
    create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_dnerror "dnerror proxy" $PROXY_VALIDITY proxy_lim
    create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_lim "limited proxy" $PROXY_VALIDITY proxy_lim

    create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_exp "proxy" -1 proxy
    create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY proxy_exp
    create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_exp "proxy" -1 proxy_exp

    create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_rfc "rfc proxy" $PROXY_VALIDITY proxy
    create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY proxy_rfc
    create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_rfc_lim "limited proxy" $PROXY_VALIDITY proxy_rfc
    create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_rfc "rfc proxy" $PROXY_VALIDITY proxy_rfc_plen
    create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_rfc "rfc proxy" $PROXY_VALIDITY proxy_rfc_lim
    create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_rfc_plen "rfc path lim 1 proxy" $PROXY_VALIDITY proxy_rfc_plen

    create_cert_proxy_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_rfc "rfc proxy" $PROXY_VALIDITY proxy_rfc_plen proxy_rfc
    create_cert_proxy_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_rfc "rfc proxy" $PROXY_VALIDITY proxy_rfc_lim proxy_rfc
    create_cert_proxy_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_rfc "rfc proxy" $PROXY_VALIDITY proxy_rfc_plen proxy_rfc_plen
    

    TYPE="clientmd5"
    CTYPE="client with md5 hash"

    create_cert $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" ${TYPE} $DAYS
    create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY
    create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_exp "proxy" -1
    create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY proxy
    create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_exp "proxy" -1 proxy

    TYPE="clientsha224"
    CTYPE="client with sha224 hash"

    create_cert $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" ${TYPE} $DAYS
    create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY
    create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_exp "proxy" -1
    create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY proxy
    create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_exp "proxy" -1 proxy

    TYPE="clientsha256"
    CTYPE="client with sha256 hash"

    create_cert $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" ${TYPE} $DAYS
    create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY
    create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_exp "proxy" -1
    create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY proxy
    create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_exp "proxy" -1 proxy

    TYPE="clientsha384"
    CTYPE="client with sha384 hash"

    create_cert $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" ${TYPE} $DAYS
    create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY
    create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_exp "proxy" -1
    create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY proxy
    create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_exp "proxy" -1 proxy

    TYPE="clientsha512"
    CTYPE="client with sha512 hash"

    create_cert $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" ${TYPE} $DAYS
    create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY
    create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_exp "proxy" -1
    create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY proxy
    create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_exp "proxy" -1 proxy

    # end of hash variations
    TYPE="clientbaddn"
    CTYPE="client with bad DN"

    create_cert $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" ${TYPE} $DAYS
    create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY
    create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_exp "proxy" -1
    create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY proxy
    create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_exp "proxy" -1 proxy

    TYPE="clientfuture"
    CTYPE="client future"

    create_cert $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" ${TYPE} $DAYS
    create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY
    create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_exp "proxy" -1
    create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY proxy
    create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_exp "proxy" -1 proxy
    
    TYPE="client_exp"
    CTYPE="client expired"
    TYPE2="client"
    
    create_cert $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" ${TYPE2} -1
    create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY
    create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY proxy
    
    TYPE="client_rev"
    CTYPE="client revoked"
    TYPE2="client"
    
    create_cert $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" ${TYPE2} $DAYS
    create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY
    create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY proxy
    openssl ca -revoke $CERT_DIR/${catype}_${TYPE}.cert -config $REQ_CONFIG_FILE

    TYPE="client_slash"
    CTYPE="client slash"
    
    create_cert $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" ${TYPE} $DAYS
    create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY
    create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY proxy
    
    if [ $catype == "trusted" ]; then
	
	TYPE="clientserial"
	CTYPE="client serial"
	
	create_cert $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" ${TYPE} $DAYS
	create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY
	create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_exp "proxy" -1
	create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY proxy
	create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_exp "proxy" -1 proxy
	
	TYPE="clientemail"
	CTYPE="client email"
	
	create_cert $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" ${TYPE} $DAYS
	create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY
	create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_exp "proxy" -1
	create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDIT $PROXY_VALIDITY proxy
	create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_exp "proxy" -1 proxy_exp
	
	TYPE="clientuid"
	CTYPE="client UID"
	
	create_cert $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" ${TYPE} $DAYS
	create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY
	create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_exp "proxy" -1
	create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY proxy
	create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_exp "proxy" -1 proxy_exp
	
	TYPE="fclient"
	CTYPE="flag client"
	
	create_cert $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" ${TYPE} $DAYS
	create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY
	create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_exp "proxy" -1
	create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY proxy
	create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_exp "proxy" -1 proxy_exp
	
	TYPE="bigclient"
	CTYPE="bigclient"
	TYPE2="client"
	
	create_cert $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" ${TYPE2} $DAYS 4096
	create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY
	create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_exp "proxy" -1
	create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY proxy
	create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_exp "proxy" -1 proxy_exp
	
	TYPE="verybigclient"
	CTYPE="very big client"
	TYPE2="client"
	
	create_cert $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" ${TYPE2} $DAYS 8192
	create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY
	create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_exp "proxy" -1
	create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY proxy
	create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_exp "proxy" -1 proxy_exp
	
	TYPE="server"
	CTYPE="server"
	
	create_cert $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" ${TYPE} $DAYS
	create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY
	create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_exp "proxy" -1
	create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY proxy
	create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_exp "proxy" -1 proxy_exp
	
	TYPE="host"
	CTYPE=$hostname_full
	TYPE2="server"
	
	create_cert $CERT_DIR/${catype}_${TYPE} "${CTYPE}" ${TYPE2} $DAYS
	
	TYPE="host_rev"
	CTYPE="CN=revoked, $hostname_full"
	TYPE2="server"
	
	create_cert $CERT_DIR/${catype}_${TYPE} "${CTYPE}" ${TYPE2} $DAYS
	openssl ca -revoke $CERT_DIR/${catype}_${TYPE}.cert -config $REQ_CONFIG_FILE
	
	
	TYPE="host_exp"
	CTYPE="$hostname_full, emailAddress=expired@expired.foo"
	TYPE2="server"

	create_cert $CERT_DIR/${catype}_${TYPE} "${CTYPE}" ${TYPE2} -1
	
	TYPE="host_baddn"
	CTYPE=$hostname_full
	TYPE2="hostbaddn"
	
	create_cert $CERT_DIR/${catype}_${TYPE} "${CTYPE}" ${TYPE2} $DAYS
	
	TYPE="host_email"
	CTYPE=$hostname_full
	TYPE2="hostemail"
	
	create_cert $CERT_DIR/${catype}_${TYPE} "${CTYPE}" ${TYPE2} $DAYS
	
	TYPE="altname"
	CTYPE="altname"
	
	create_cert $CERT_DIR/${catype}_${TYPE} "$catype\/xxx.foo.bar" ${TYPE} $DAYS
	
	TYPE="altname"
	CTYPE="altname"
	
	create_cert $CERT_DIR/${catype}_${TYPE}_2 "$catype altname/CN=xxx.foo.bar" ${TYPE} $DAYS

	echo $DNS_HOSTNAME
	
	TYPE="altname2"
	CTYPE="altname"
	
	create_cert $CERT_DIR/${catype}_${TYPE} "$catype hostname only in altname" ${TYPE} $DAYS
	
	TYPE="altname2"
	CTYPE="altname"
	
	create_cert $CERT_DIR/${catype}_${TYPE}_2 "$catype altname cont hostname/CN=$hostname_full" ${TYPE} $DAYS
	
	TYPE="altname3"
	CTYPE="altname"
	
	create_cert $CERT_DIR/${catype}_${TYPE} "$catype altname but no hostname anywhere" ${TYPE} $DAYS
	
	TYPE="altname3"
	CTYPE="altname"
	
	create_cert $CERT_DIR/${catype}_${TYPE}_2 "$catype altname without hostname/CN=$hostname_full" ${TYPE} $DAYS
	
	TYPE="server"
	CTYPE="server2"
	
	create_cert $CERT_DIR/${catype}_${TYPE}2 "xxx2.foo.bar" ${TYPE} $DAYS
	
	TYPE="clientserver"
	CTYPE="clientserver"
	
	create_cert $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" ${TYPE} $DAYS
	create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY
	create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_exp "proxy" -1
	create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY proxy
	create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_exp "proxy" -1 proxy_exp

	TYPE="none"
	CTYPE="none"
	
	create_cert $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" ${TYPE} $DAYS
	create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY
	create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_exp "proxy" -1
	create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY proxy
	create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy_exp "proxy" -1 proxy_exp
	
    # create certs with valid proxies, but expired user certs
	
	TYPE="fclient_exp"
	CTYPE="flag client expired"
	TYPE2="fclient"
	
	create_cert $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" ${TYPE2} -1
	create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY
	create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY proxy

	TYPE="server_exp"
	CTYPE="flag server expired"
	TYPE2="server"
	
	create_cert $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" ${TYPE2} -1
	create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY
	create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY proxy
	
	TYPE="clientserver_exp"
	CTYPE="clientserver expired"
	TYPE2="clientserver"
	
	create_cert $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" ${TYPE2} -1
	create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY
	create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY proxy
    
	TYPE="none_exp"
	CTYPE="none expired"
	TYPE2="none"
	
	create_cert $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" ${TYPE2} -1
	create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY
	create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY proxy
	
    # Create revoked certificates with otherwise valid proxies
	
	TYPE="fclient_rev"
	CTYPE="flag client revoked"
	TYPE2="fclient"
	
	create_cert $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" ${TYPE2} $DAYS
	create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY
	create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY proxy
	openssl ca -revoke $CERT_DIR/${catype}_${TYPE}.cert -config $REQ_CONFIG_FILE
    
	TYPE="server_rev"
	CTYPE="server revoked"
	TYPE2="server"
	
	create_cert $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" ${TYPE2} $DAYS
	create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY
	create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY proxy
	openssl ca -revoke $CERT_DIR/${catype}_${TYPE}.cert -config $REQ_CONFIG_FILE
	
	TYPE="clientserver_rev"
	CTYPE="clientserver revoked"
	TYPE2="clientserver"
	
	create_cert $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" ${TYPE2} $DAYS
	create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY
	create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY proxy
	openssl ca -revoke $CERT_DIR/${catype}_${TYPE}.cert -config $REQ_CONFIG_FILE
	
	TYPE="none_rev"
	CTYPE="none revoked"
	TYPE2="none"
	
	create_cert $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" ${TYPE2} $DAYS
	create_cert_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY
	create_cert_proxy_proxy $CERT_DIR/${catype}_${TYPE} "$catype ${CTYPE}" proxy "proxy" $PROXY_VALIDITY proxy
	openssl ca -revoke $CERT_DIR/${catype}_${TYPE}.cert -config $REQ_CONFIG_FILE
	
    fi

    if [ $catype == "subsubca" ]; then
	CACHAIN="$CERT_DIR/tmp.tmp"
	openssl x509 -in subsubca-ca/subsubca.cert > ${CACHAIN}
	openssl x509 -in subca-ca/subca.cert >> ${CACHAIN}
	
	cp $CERT_DIR/subsubca_client.proxy.grid_proxy $CERT_DIR/subsubca_fullchainclient.proxy.grid_proxy
	cat $CACHAIN >> $CERT_DIR/subsubca_fullchainclient.proxy.grid_proxy
	cp $CERT_DIR/subsubca_client.proxy.proxy.grid_proxy $CERT_DIR/subsubca_fullchainclient.proxy.proxy.grid_proxy
	cat $CACHAIN >> $CERT_DIR/subsubca_fullchainclient.proxy.proxy.grid_proxy
    fi

    # generating CRL
    CMD="openssl ca -gencrl -crldays $DAYS -out $CA_DIR/${catype}.crl -config $REQ_CONFIG_FILE"
    echo $CMD; eval $CMD

    if [ $? != 0 ]; then
	echo CRL file generation failed! Aborting.
	exit 1
    fi
    
    #generate crl with extension
    CMD="openssl ca -gencrl -crldays $DAYS -out $CA_DIR/${catype}.crl_ext -config $REQ_CONFIG_FILE -crlexts crl_section"
    echo $CMD; eval $CMD

    if [ $? != 0 ]; then
	echo CRL file generation failed! Aborting.
	exit 1
    fi

    # If we have the trusted CA, then generate a user cert/key pair
    # And also a host cert/key pair.

    echo adding CA $catype to grid-security 

    if [ "$catype" == "trusted" ]; then
        create_some
    else
	# othewise if the ca is not the fake one, add them to the grid-security/certificates directory
	if [ "$catype" != "fake" ]; then
	    echo really adding the CA $catype
	    add_ca_grid_sec $catype
	    # if this is the subsubca, add also the root and subca.
	    if [ "$catype" = 'subsubca' ]; then
                # generating CRL
		openssl ca -gencrl -crldays $DAYS -out root-ca/root.crl -config root-ca/req_conf.cnf 
		openssl ca -gencrl -crldays $DAYS -out subca-ca/subca.crl -config subca-ca/req_conf.cnf 
		echo subsub ca, add root and subca
		add_ca_grid_sec root
		add_ca_grid_sec subca
	    fi
	fi
    fi

    # now do the clean-up?
    rm ${CA_DIR}/serial_proxy.txt ${CA_DIR}/index_proxy.txt ${CA_DIR}/serial_cert_save.txt ${CA_DIR}/index_cert_save.txt

}

############################## main ################################

USAGE="$0 [--help] [--all|--some] [--voms] [--onlyenv] [--extra #extra-user-certs] target_dir"

TEMP=$(getopt -o hasvoe: --long help,all,some,voms,onlyenv,extra: -- "$@")
eval set -- "$TEMP"

# by default do not create all variations of certificates
ALL='no'
# by default only create trusted certificates
CATYPES='trusted'
# by default create 5 extra user certificates
EXTRACERTS=${EXTRACERTS:-5}
# by default fake VOMS certificate are also created
VOMS='no'
# if we only show environmental settings
ONLYENV='no'
USENEWHASH='no'

while true; do
    case "$1" in
        -a|--all)
            ALL='yes'
            CATYPES='trusted fake bad big expired nokeyusage subsubca slash'
#           CATYPES='trusted'
            shift
            ;;
        -s|--some)
            ALL='no'
            CATYPES='trusted'
            shift
            ;;
        -n|--new)
            USENEWHASH='true'
            shift
            ;;
        -e|--extra)
            shift
            EXTRACERTS=$1
            shift
            ;;
        -v|--voms)
            VOMS='yes'
            shift
            ;;
        -o|--onlyenv)
            ONLYENV='yes'
            CATYPES=''
            ALL='no'
            shift
            ;;
        -h|--help)
            echo $USAGE
            exit
            ;;
        --)
            # end of options
            shift
            break
            ;;
        *)
            echo "Error: unknown option '$1'"
            echo $USAGE
            exit 1
    esac
done

echo openssl command and version:
which openssl
openssl version

#get full hostname
hostname_space=`hostname -A 2>/dev/null || hostname -f`
#remove trailing space, take fist one if there are aliases
hostname_full=`echo $hostname_space | awk '{print $1}'`
if [ x${hostname_full} == "x" ]; then
hostname_full=`hostname -f`
fi

echo host name is [$hostname_full]

export DNS_HOSTNAME=DNS:$hostname_full
echo dns hostname string is [$DNS_HOSTNAME]

#define all used dirs    
TARGETDIR=$1
CONFIGDIR=$(cd $(dirname $0)/..; echo $PWD)/test

PASSWORD='changeit'
DAYS=5000

if [ -z "$TARGETDIR" ]; then
    echo "Please specify the destination directory!"
    exit -1
fi

if [ ! -d "$TARGETDIR" ]; then
    mkdir -p $TARGETDIR
fi
cd $TARGETDIR
# set it to an absolute path
TARGETDIR=$PWD
[ "$ONLYENV" = 'yes' ] || echo "Target directory: ${TARGETDIR}"
[ "$ONLYENV" = 'yes' ] || echo "Config directory: ${CONFIGDIR}"

tmpdir=$TARGETDIR/tmp
mkdir -p $tmpdir
trap "rm -rf $tmpdir" EXIT

for catype in $CATYPES; do
    echo "+-----------------------"
    echo "| $catype"
    echo "+-----------------------"
    cd $TARGETDIR

    CA_DIR=${catype}-ca
    CERT_DIR=${catype}-certs
    REQ_CONFIG_FILE=$CA_DIR/req_conf.cnf
    PROXY_BITS=1024
    # this is needed for the req_config.cnf to work
    export CASROOT=./

    # putting the CA certificate to the right place
    copy_ca "$CONFIGDIR/${catype}-ca" "$CA_DIR"
    # if the CA is subsubca, copy also the parents
    if [ "$catype" = "subsubca" ]; then
	copy_ca "$CONFIGDIR/subca-ca" "subca-ca"
	copy_ca "$CONFIGDIR/root-ca" "root-ca"
    fi

    mkdir -p $CERT_DIR
    
    if [ "$ALL" = "yes" ]; then
	create_all
    else
	create_some
    fi
#    rm $CA_DIR/*.pem
    rm $CA_DIR/*.old
    rm $CA_DIR/*.attr
done



[ "$ONLYENV" = 'yes' ] || echo "Easy usage environmental variable settings:"
echo "export X509_CERT_DIR=$TARGETDIR/grid-security/certificates"
echo "export X509_USER_CERT=$TARGETDIR/home/usercert.pem"
echo "export X509_USER_KEY=$TARGETDIR/home/userkey.pem"
if [ "$VOMS" = 'yes' ]; then
    echo "export X509_VOMS_DIR=$TARGETDIR/grid-security/vomsdir"
fi

cat >$TARGETDIR/home/env_settings.sh <<EOF
#!/bin/bash

###################################################################
# Copyright (c) Members of the EGEE Collaboration. 2004. See
# http://www.eu-egee.org/partners/ for details on the copyright holders.
# 
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy of
# the License at
# 
# http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.
#
# Instantiates the configuration templates of this package.
#
# Author: Akos.Frohner@cern.ch
# Author: Joni.Hahkala@cern.ch
#
###################################################################


export X509_CERT_DIR=$TARGETDIR/grid-security/certificates
export X509_USER_CERT=$TARGETDIR/home/usercert.pem
export X509_USER_KEY=$TARGETDIR/home/userkey.pem
export X509_VOMS_DIR=$TARGETDIR/grid-security/vomsdir
EOF

