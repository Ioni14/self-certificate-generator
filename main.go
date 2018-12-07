package main

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "fmt"
    "io/ioutil"
    "math/big"
    "os"
    "time"
)

func generateCA() {
    // Generate 2048bit RSA Key
    key, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Cannot generate RSA key : %s\n", err)
        os.Exit(1)
    }
    fmt.Println("CA RSA Key generated.")

    // Generate CA Certificate
    certTemplate := x509.Certificate{
        SerialNumber: big.NewInt(1),
        Subject: pkix.Name{
            Organization: []string{"Self Certificate Generator"},
            CommonName: "Root CA",
        },
        NotBefore: time.Now(),
        NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
        KeyUsage: x509.KeyUsageDigitalSignature|x509.KeyUsageCRLSign|x509.KeyUsageCertSign,
        IsCA: true,
        BasicConstraintsValid: true,
    }
    cert, err := x509.CreateCertificate(rand.Reader, &certTemplate, &certTemplate, key.Public(), key)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Cannot create CA certificate : %s\n", err)
        os.Exit(1)
    }
    fmt.Println("CA Certificate created.")

    // write CA Key
    caKeyOut, err := os.OpenFile("ca.key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Cannot open file ca.key.pem : %s\n", err)
        os.Exit(1)
    }
    err = pem.Encode(caKeyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
    if err != nil {
        fmt.Fprintf(os.Stderr, "Cannot encode RSA key in PEM : %s\n", err)
        os.Exit(1)
    }
    err = caKeyOut.Close()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Cannot close ca.key.pem : %s\n", err)
        os.Exit(1)
    }
    fmt.Println("CA RSA Private Key written in ca.key.pem.")

    // Write CA Certificate
    caCertOut, err := os.OpenFile("ca.cert.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Cannot open file ca.cert.pem : %s\n", err)
        os.Exit(1)
    }
    err = pem.Encode(caCertOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
    if err != nil {
        fmt.Fprintf(os.Stderr, "Cannot encode CA Certificate in PEM : %s\n", err)
        os.Exit(1)
    }
    err = caCertOut.Close()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Cannot close ca.cert.pem : %s\n", err)
        os.Exit(1)
    }
    fmt.Println("CA Certificate written in ca.cert.pem.")
}

func generateServerCertificate() {
    // Generate 2048bit RSA Key
    key, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Cannot generate RSA key : %s\n", err)
        os.Exit(1)
    }
    fmt.Println("Server RSA Key generated.")

    // write CA Key
    caKeyOut, err := os.OpenFile("server.key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Cannot open file server.key.pem : %s\n", err)
        os.Exit(1)
    }
    err = pem.Encode(caKeyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
    if err != nil {
        fmt.Fprintf(os.Stderr, "Cannot encode RSA key in PEM : %s\n", err)
        os.Exit(1)
    }
    err = caKeyOut.Close()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Cannot close ca.key.pem : %s\n", err)
        os.Exit(1)
    }
    fmt.Println("Server RSA Private Key written in server.key.pem.")

    // Create Server CSR
    certRequestTemplate := x509.CertificateRequest{
        Subject: pkix.Name{
            Organization: []string{"Self Certificate Generator"},
            CommonName: "*.server.test",
        },
        DNSNames: []string{"*.server.test"},
    }
    certRequest, err := x509.CreateCertificateRequest(rand.Reader, &certRequestTemplate, key)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Cannot create Server certificate signing request : %s\n", err)
        os.Exit(1)
    }
    fmt.Println("Server certificate signing request created.")

    // Write Server CSR
    serverCertRequestOut, err := os.OpenFile("server.csr.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Cannot open file server.csr.pem : %s\n", err)
        os.Exit(1)
    }
    err = pem.Encode(serverCertRequestOut, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: certRequest})
    if err != nil {
        fmt.Fprintf(os.Stderr, "Cannot encode Server Certificate Signing Request in PEM : %s\n", err)
        os.Exit(1)
    }
    err = serverCertRequestOut.Close()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Cannot close server.csr.pem : %s\n", err)
        os.Exit(1)
    }
    fmt.Println("Server certificate signing request written in server.csr.pem.")

    caCertFile, err := ioutil.ReadFile("ca.cert.pem")
    if err != nil {
        fmt.Fprintf(os.Stderr, "Cannot read ca.cert.pem : %s\n", err)
        os.Exit(1)
    }
    caCertPem, _ := pem.Decode(caCertFile)
    if caCertPem == nil {
        fmt.Fprintf(os.Stderr, "Failed to decode ca.cert.pem.")
        os.Exit(1)
    }
    caCert, err := x509.ParseCertificate(caCertPem.Bytes)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Cannot parse CA certificate : %s\n", err)
        os.Exit(1)
    }
    fmt.Println("CA Certificate retrieved.")

    caKeyFile, err := ioutil.ReadFile("ca.key.pem")
    if err != nil {
        fmt.Fprintf(os.Stderr, "Cannot read ca.key.pem : %s\n", err)
        os.Exit(1)
    }
    caKeyPem, _ := pem.Decode(caKeyFile)
    if caKeyPem == nil {
        fmt.Fprintf(os.Stderr, "Failed to decode ca.key.pem.")
        os.Exit(1)
    }
    // der, err := x509.DecryptPEMBlock(caKeyPem, []byte{"password"})
    // if err != nil {
    //     fmt.Fprintf(os.Stderr, "Cannot decrypt ca.key.pem : %s\n", err)
    //     os.Exit(1)
    // }
    caKey, err := x509.ParsePKCS1PrivateKey(caKeyPem.Bytes)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Cannot parse ca.key.pem : %s\n", err)
        os.Exit(1)
    }
    fmt.Println("CA Key retrieved.")

    certDnsNames := make([]string, len(certRequestTemplate.DNSNames)/*, (cap(certRequestTemplate.DNSNames)+1)*2*/)
    copy(certDnsNames, certRequestTemplate.DNSNames)
    serverCertTemplate := x509.Certificate{
        Signature: certRequestTemplate.Signature,
        SignatureAlgorithm: certRequestTemplate.SignatureAlgorithm,
        PublicKey: certRequestTemplate.PublicKey,
        PublicKeyAlgorithm: certRequestTemplate.PublicKeyAlgorithm,

        SerialNumber: big.NewInt(1),
        Issuer: caCert.Subject,
        Subject: certRequestTemplate.Subject,
        NotBefore: time.Now(),
        NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
        KeyUsage: x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment,
        ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
        DNSNames: certDnsNames,
    }
    serverCert, err := x509.CreateCertificate(rand.Reader, &serverCertTemplate, caCert, key.Public(), caKey)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Cannot create server certificate : %s\n", err)
        os.Exit(1)
    }
    fmt.Println("Server certificate created.")

    // Write CA Certificate
    serverCertOut, err := os.OpenFile("server.cert.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Cannot open file server.cert.pem : %s\n", err)
        os.Exit(1)
    }
    err = pem.Encode(serverCertOut, &pem.Block{Type: "CERTIFICATE", Bytes: serverCert})
    if err != nil {
        fmt.Fprintf(os.Stderr, "Cannot encode Server certificate in PEM : %s\n", err)
        os.Exit(1)
    }
    err = serverCertOut.Close()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Cannot close server.cert.pem : %s\n", err)
        os.Exit(1)
    }
    fmt.Println("Server certificate written in server.cert.pem.")
}

func main() {
    generateCA()
    generateServerCertificate()
}
