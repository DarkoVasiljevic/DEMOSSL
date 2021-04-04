#pragma once

#define _CRT_SECURE_NO_WARNINGS

#ifndef _CERT_HPP
#define _CERT_HPP

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <openssl/bn.h>

#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <stdexcept>

#define BUFFER (2048)

class Certificate {

private:
	const char* _root_ca_path = "..\\Root_CA\\root_ca.crt";
	const char* _root_ca_privateKey_path = "..\\Root_CA\\ca_private_key.pem";
	const char* _root_ca_publicKey_path = "..\\Root_CA\\ca_public_key.pem";
	const char* _new_cert_path = "..\\New_cert\\new_cert.crt";
	const char* _cert_req_path = "..\\Cert_req\\cert_req.csr";
	const char* _cert_req_privateKey_path = "..\\Cert_req\\cr_private_key.pem";
	const char* _cert_req_publicKey_path = "..\\Cert_req\\cr_public_key.pem";
	const char* _szCountry = "RS";
	const char* _szCity = "Belgrade";
	const char* _szCommon = "RootCARequest";
	const char* _szOrganization = "NetTestRequest";
	const char* _ca_szCommon = "RootCA";
	const char* _ca_szOrganization = "NetTest";

public:
	Certificate() {}

private:
	void generateRsaKey(EVP_PKEY**);
	void writeCAPrivateKey(EVP_PKEY**);
	void writeCAPublicKey(EVP_PKEY**);
	void writeCACert(X509**);
	void writeCertReqPrivateKey(EVP_PKEY**);
	void writeCertReqPublicKey(EVP_PKEY**);
	void writeCertRequest(X509_REQ**);
	void writeCertFromRequest(X509**);

public:
	void generateRootCA();
	void generateCertRequest();
	void generateCertFromRequest();
	void readCACertFromFile(unsigned char*);
	void readCertReqFromFile(unsigned char*);
	void readCertFromReqFromFile(unsigned char*);
	
	~Certificate() {}
};

#endif //_SIGN_HPP

