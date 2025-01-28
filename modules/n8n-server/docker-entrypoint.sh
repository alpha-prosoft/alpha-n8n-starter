#!/bin/sh
if [ -d /opt/custom-certificates ]; then
  echo "Trusting custom certificates from /opt/custom-certificates."
  export NODE_OPTIONS=--use-openssl-ca $NODE_OPTIONS
  export SSL_CERT_DIR=/opt/custom-certificates
  c_rehash /opt/custom-certificates
fi

if [ "$#" -gt 0 ]; then
  # Got started with arguments
  if [ "${DEBUG:-}" == "True" ]; then
  	echo "Starting in debug mode with params"
  	nodemon --watch /home/node/.n8n/custom/nodes \
            --watch /home/node/.n8n/custom/credentials \
            --ext ts,js,json \
            --exec 'n8n'
  else
  	echo "Starting in normal mode with params"
    exec n8n "$@"
  fi
else
  # Got started without arguments
  if [ "${DEBUG:-}" == "True" ]; then
  	echo "Starting in debug mode"
  	nodemon --watch /home/node/.n8n/custom/nodes \
            --watch /home/node/.n8n/custom/credentials \
            --ext ts,js,json \
            --exec 'n8n'
  else
		echo "Starting in normal mode"
  	exec n8n
  fi
fi
