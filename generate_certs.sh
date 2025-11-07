#!/bin/bash

echo "🔐 Generating TLS 1.3 Certificates for Secure File Sharing..."

# Check OpenSSL
if ! command -v openssl &> /dev/null; then
    echo "❌ OpenSSL not found. Installing..."
    sudo apt update && sudo apt install -y openssl
fi

# Generate RSA 2048 private key
echo "📝 Generating RSA 2048 private key..."
openssl genrsa -out server.key 2048

# Generate self-signed certificate with proper extensions for TLS 1.3
echo "📄 Generating X.509 certificate..."
openssl req -new -x509 -key server.key -out server.crt -days 365 \
    -subj "/C=US/ST=California/L=San Francisco/O=Secure File Sharing/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    -addext "keyUsage=digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth"

# Secure permissions
chmod 600 server.key
chmod 644 server.crt

echo ""
echo "✅ TLS 1.3 Certificates Generated Successfully!"
echo "🔒 Security Features:"
echo "   • RSA 2048 Encryption"
echo "   • X.509 Certificate"
echo "   • Subject Alternative Name (SAN)"
echo "   • TLS Server Authentication"
echo "   • 1-Year Validity"
echo ""
echo "🚀 Certificates are ready for TLS 1.3 encryption"