package main

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "errors"
    "flag"
    "fmt"
    "io/ioutil"
    "math/big"
    "os"
    "time"
)

func generateCA(certFilename string, keyFilename string) (*x509.Certificate, *rsa.PrivateKey, error) {
    // Generate 2048bit RSA Key
    key, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return nil, nil, errors.New(fmt.Sprintf("Cannot generate RSA key : %s", err))
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
        return nil, nil, errors.New(fmt.Sprintf("Cannot create CA certificate : %s", err))
    }
    fmt.Println("CA Certificate created.")

    // write CA Key
    caKeyOut, err := os.OpenFile(keyFilename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
    if err != nil {
        return nil, nil, errors.New(fmt.Sprintf("Cannot open file %s : %s", keyFilename, err))
    }
    err = pem.Encode(caKeyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
    if err != nil {
        return nil, nil, errors.New(fmt.Sprintf("Cannot encode RSA key in PEM %s : %s", keyFilename, err))
    }
    err = caKeyOut.Close()
    if err != nil {
        return nil, nil, errors.New(fmt.Sprintf("Cannot close %s : %s", keyFilename, err))
    }
    fmt.Printf("CA RSA Private Key written in %s.\n", keyFilename)

    // Write CA Certificate
    caCertOut, err := os.OpenFile(certFilename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
    if err != nil {
        return nil, nil, errors.New(fmt.Sprintf("Cannot open file %s : %s", keyFilename, err))
    }
    err = pem.Encode(caCertOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
    if err != nil {
        return nil, nil, errors.New(fmt.Sprintf("Cannot encode CA Certificate in PEM %s : %s", keyFilename, err))
    }
    err = caCertOut.Close()
    if err != nil {
        return nil, nil, errors.New(fmt.Sprintf("Cannot close %s : %s", keyFilename, err))
    }
    fmt.Printf("CA Certificate written in %s.\n", certFilename)

    return &certTemplate, key, nil
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

func parseCaCert(filepath string) (*x509.Certificate, error) {
    caCertFile, err := ioutil.ReadFile(filepath)
    if err != nil {
        return nil, errors.New(fmt.Sprintf("Cannot read %s : %s", filepath, err))
    }
    caCertPem, _ := pem.Decode(caCertFile)
    if caCertPem == nil {
        return nil, errors.New(fmt.Sprintf("Failed to PEM decode %s.", filepath))
    }
    caCert, err := x509.ParseCertificate(caCertPem.Bytes)
    if err != nil {
        return nil, errors.New(fmt.Sprintf("Cannot parse Certificate %s : %s", filepath, err))
    }

    return caCert, nil
}
func parseRsaKey(filepath string, password *string) (*rsa.PrivateKey, error) {
    caKeyFile, err := ioutil.ReadFile(filepath)
    if err != nil {
        return nil, errors.New(fmt.Sprintf("Cannot read %s : %s", filepath, err))
    }
    caKeyPem, _ := pem.Decode(caKeyFile)
    if caKeyPem == nil {
        return nil, errors.New(fmt.Sprintf("Failed to PEM decode %s.", filepath))
    }
    var der []byte
    if password != nil {
        der, err = x509.DecryptPEMBlock(caKeyPem, []byte(*password))
        if err != nil {
            return nil, errors.New(fmt.Sprintf("Cannot decrypt RSA Key %s : %s", filepath, err))
        }
    } else {
        der = caKeyPem.Bytes
    }
    caKey, err := x509.ParsePKCS1PrivateKey(der)
    if err != nil {
        return nil, errors.New(fmt.Sprintf("Cannot parse RSA Key %s (missing password ?) : %s", filepath, err))
    }

    return caKey, nil
}

func main() {
    wantToGenerateCa := flag.Bool("gen-ca", false, "Would you want to generate a CA ? The key and certificate will be created at --ca-key and --ca-cert paths.")
    caCertFilename := flag.String("ca-cert", "", "Path to your existing or destination CA Certificate PEM (e.g., /path/to/ca.cert.pem).")
    caKeyFilename := flag.String("ca-key", "", "Path to your existing or destination CA Key PEM (e.g., /path/to/ca.key.pem). Use the env CA_KEY_PASSWORD if it's encrypted, otherwise leave it blank.")
    serverCertFilename := flag.String("server-cert", "", "Path to your existing Server Certificate PEM (e.g., /path/to/server.cert.pem).")
    flag.Parse()

    if len(os.Args) <= 1 { // only program path
        flag.Usage()
        os.Exit(0)
    }

    fmt.Println(*serverCertFilename)

    var caCert *x509.Certificate = nil
    var caKey *rsa.PrivateKey = nil
    var err error
    if *wantToGenerateCa {
        if len(*caCertFilename) == 0 {
            *caCertFilename = "ca.cert.pem"
        }
        if len(*caKeyFilename) == 0 {
            *caKeyFilename = "ca.key.pem"
        }
        fmt.Printf("Generating CA Certificate %s and CA Key %s...\n", *caCertFilename, *caKeyFilename)

        caCert, caKey, err = generateCA(*caCertFilename, *caKeyFilename)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Cannot generate CA : %s\n", err)
            os.Exit(1)
        }

        fmt.Printf("CA generated.\nCertificate : %s. Key : %s.\n", *caCertFilename, *caKeyFilename)
    } else if len(*caCertFilename) != 0 && len(*caKeyFilename) != 0 {
        fmt.Println("Custom CA Certificate and CA Key given : try to parse them...")

        caCert, err = parseCaCert(*caCertFilename)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Cannot parse custom CA Certificate : %s\n", err)
            os.Exit(1)
        }

        caKeyPassword := os.Getenv("CA_KEY_PASSWORD")
        var password *string = nil
        if len(caKeyPassword) > 0 {
            password = &caKeyPassword
        }
        caKey, err = parseRsaKey(*caKeyFilename, password)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Cannot parse custom CA Key : %s\n", err)
            os.Exit(1)
        }

        fmt.Println("Custom CA Certificate and CA Key parsed.")
    }
    fmt.Println(caCert.Subject.CommonName, caKey.Public())

    generateServerCertificate()
}
