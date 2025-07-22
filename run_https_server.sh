#!/bin/bash

sudo openssl s_server -accept 443 -cert cert.pem -key key.pem
