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
    "strings"
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

func generateServerCertificate(
    serial *big.Int,
    certFilename string,
    /*csrFilename string,*/
    keyFilename string,
    domains []string,
    caCert *x509.Certificate,
    caKey *rsa.PrivateKey) (*rsa.PrivateKey, /**x509.CertificateRequest, */*x509.Certificate, error) {
    if len(domains) == 0 {
        return nil, nil, errors.New(fmt.Sprintf("No domains provided for generating server certificate."))
    }

    // Generate 2048bit RSA Key
    key, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return nil, nil, errors.New(fmt.Sprintf("Cannot generate RSA key : %s", err))
    }
    fmt.Println("Server RSA Key generated.")

    // write CA Key
    serverKeyOut, err := os.OpenFile(keyFilename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
    if err != nil {
        return nil, nil, errors.New(fmt.Sprintf("Cannot open file %s : %s", keyFilename, err))
    }
    err = pem.Encode(serverKeyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
    if err != nil {
        return nil, nil, errors.New(fmt.Sprintf("Cannot encode RSA key in PEM %s : %s", keyFilename, err))
    }
    err = serverKeyOut.Close()
    if err != nil {
        return nil, nil, errors.New(fmt.Sprintf("Cannot close %s : %s", keyFilename, err))
    }
    fmt.Printf("Server RSA Private Key written in %s.\n", keyFilename)

    // Create Server CSR
    certRequestTemplate := x509.CertificateRequest{
        Subject: pkix.Name{
            Organization: []string{"Self Certificate Generator"},
            CommonName: domains[0],
        },
        DNSNames: domains,
    }
    // certRequest, err := x509.CreateCertificateRequest(rand.Reader, &certRequestTemplate, key)
    // if err != nil {
    //     return nil, nil, errors.New(fmt.Sprintf("Cannot create Server certificate signing request : %s", err))
    // }
    // fmt.Println("Server certificate signing request created.")

    // Write Server CSR
    // serverCertRequestOut, err := os.OpenFile(csrFilename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
    // if err != nil {
    //     return nil, nil, errors.New(fmt.Sprintf("Cannot open file %s : %s", csrFilename, err))
    // }
    // err = pem.Encode(serverCertRequestOut, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: certRequest})
    // if err != nil {
    //     return nil, nil, errors.New(fmt.Sprintf("Cannot encode Server certificate signing request in PEM %s : %s", csrFilename, err))
    // }
    // err = serverCertRequestOut.Close()
    // if err != nil {
    //     return nil, nil, errors.New(fmt.Sprintf("Cannot close %s : %s", csrFilename, err))
    // }
    // fmt.Printf("Server certificate signing request written in %s.\n", csrFilename)

    certDnsNames := make([]string, len(certRequestTemplate.DNSNames))
    copy(certDnsNames, certRequestTemplate.DNSNames)
    serverCertTemplate := x509.Certificate{
        Signature: certRequestTemplate.Signature,
        SignatureAlgorithm: certRequestTemplate.SignatureAlgorithm,
        PublicKey: certRequestTemplate.PublicKey,
        PublicKeyAlgorithm: certRequestTemplate.PublicKeyAlgorithm,

        SerialNumber: serial,
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
        return nil, nil, errors.New(fmt.Sprintf("Cannot create server certificate : %s", err))
    }
    fmt.Println("Server certificate created.")

    // Write CA Certificate
    serverCertOut, err := os.OpenFile(certFilename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
    if err != nil {
        return nil, nil, errors.New(fmt.Sprintf("Cannot open file %s : %s", certFilename, err))
    }
    err = pem.Encode(serverCertOut, &pem.Block{Type: "CERTIFICATE", Bytes: serverCert})
    if err != nil {
        return nil, nil, errors.New(fmt.Sprintf("Cannot encode Server certificate in PEM %s : %s", certFilename, err))
    }
    err = serverCertOut.Close()
    if err != nil {
        return nil, nil, errors.New(fmt.Sprintf("Cannot close %s : %s", certFilename, err))
    }
    fmt.Printf("Server certificate written in %s.\n", certFilename)

    return key, /*&certRequestTemplate, */&serverCertTemplate, nil
}

func parseCert(filepath string) (*x509.Certificate, error) {
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
    wantToGenerateCa := flag.Bool("gen-ca", false, "Would you want to generate a CA ? The key and certificate will be created at --ca-key and --ca-cert paths, defaults to $PWD/ca.cert.pem and $PWD/ca.key.pem. Beware! The existing files will be overriden!")
    caCertFilename := flag.String("ca-cert", "", "Path to your existing or destination CA Certificate PEM (e.g., /path/to/ca.cert.pem).")
    caKeyFilename := flag.String("ca-key", "", "Path to your existing or destination CA RSA Key PEM (e.g., /path/to/ca.key.pem). Use the env CA_KEY_PASSWORD if it's encrypted, otherwise leave it blank.")
    serverCertFilename := flag.String("server-cert", "", "Path to your existing or destination Server Certificate PEM (e.g., /path/to/server.cert.pem).")
    serverKeyFilename := flag.String("server-key", "", "Path to your existing or destination Server RSA Key PEM (e.g., /path/to/server.key.pem).")
    serverDomainsStr := flag.String("server-domains", "", "Comma separated domains of the server certificate (e.g., example.com,*.example.com).")
    serverCertSerial := flag.Int64("server-cert-serial", 0, "Custom serial for the server certificate.")
    flag.Parse()

    if len(os.Args) <= 1 { // only program path
        flag.Usage()
        os.Exit(0)
    }

    if len(*serverDomainsStr) == 0 {
        fmt.Fprintf(os.Stderr, "You must pass server domain(s) via --server-domains argument.\n")
        os.Exit(1)
    }

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

        caCert, err = parseCert(*caCertFilename)
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

    if caCert == nil || caKey == nil {
        fmt.Fprintf(os.Stderr, "No CA provided. Please use --ca-cert and --ca-key. You can generate one by adding --gen-ca (Beware! The existing files will be overriden!).")
        os.Exit(1)
    }

    // Generate a new server certificate
    if len(*serverCertFilename) == 0 {
        *serverCertFilename = "server.cert.pem"
    }
    if len(*serverKeyFilename) == 0 {
        *serverKeyFilename = "server.key.pem"
    }
    serverDomains := strings.Split(*serverDomainsStr, ",")

    // Does Server certificate exist ?
    serial := big.NewInt(1)
    if *serverCertSerial > 0 {
        serial.SetInt64(*serverCertSerial)
    } else {
        serverCert, err := parseCert(*serverCertFilename)
        if err == nil { // exist
            serial.SetInt64(serverCert.SerialNumber.Int64() + 1)
        }
    }

    fmt.Printf("Generating Server certificate %s and Server key %s...\n", *serverCertFilename, *serverKeyFilename)
    _, _, err = generateServerCertificate(serial, *serverCertFilename, *serverKeyFilename, serverDomains, caCert, caKey)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Cannot generate server certificate : %s.\n", err)
        os.Exit(1)
    }

    fmt.Printf("Server certificate generated.\nCertificate : %s. Key : %s.\n", *serverCertFilename, *serverKeyFilename)
}
