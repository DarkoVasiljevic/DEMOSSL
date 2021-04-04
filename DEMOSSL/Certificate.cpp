#include "Certificate.h"

void Certificate::writeCAPrivateKey(EVP_PKEY** pKey)
{
    FILE* fp = fopen(_root_ca_privateKey_path, "w");

    bool ret = PEM_write_PrivateKey(fp, *pKey, NULL, NULL, 0, NULL, NULL);

    fclose(fp);
}

void Certificate::writeCAPublicKey(EVP_PKEY** pKey)
{
    FILE* fp = fopen(_root_ca_publicKey_path, "w");

    bool ret = PEM_write_PUBKEY(fp, *pKey);

    fclose(fp);
}

void Certificate::writeCACert(X509** root_ca)
{
    int error = 0;

    FILE* fp = fopen(_root_ca_path, "w");
    error = PEM_write_X509(fp, *root_ca);

    fclose(fp);
}

void Certificate::readCACertFromFile(unsigned char* buffer) 
{
    FILE* fp = fopen(_root_ca_path, "r");
    if (fp == NULL) throw std::runtime_error(__func__);

    char c;
    int i = 0;
    while ((c = fgetc(fp)) != EOF)
        buffer[i++] = c;

    buffer[i] = '\0';

    fclose(fp);
}

void Certificate::generateRootCA()
{
    X509* root_ca = X509_new();

    ASN1_INTEGER_set(X509_get_serialNumber(root_ca), 1);

    X509_gmtime_adj(X509_get_notBefore(root_ca), 0);
    
    X509_gmtime_adj(X509_get_notAfter(root_ca), 365 * 24 * 60 * 60L);

    EVP_PKEY* pkey = NULL;
    generateRsaKey(&pkey);
    writeCAPrivateKey(&pkey);
    writeCAPublicKey(&pkey);

    X509_set_pubkey(root_ca, pkey);

    X509_NAME* root_name = X509_get_subject_name(root_ca);

    X509_NAME_add_entry_by_txt(root_name, "C", MBSTRING_ASC,
                                (unsigned char*)_szCountry, -1, -1, 0);
    X509_NAME_add_entry_by_txt(root_name, "L", MBSTRING_ASC,
                                (unsigned char*)_szCity, -1, -1, 0);
    X509_NAME_add_entry_by_txt(root_name, "O", MBSTRING_ASC,
                                (unsigned char*)_ca_szOrganization, -1, -1, 0);
    X509_NAME_add_entry_by_txt(root_name, "CN", MBSTRING_ASC,
                                (unsigned char*)_ca_szCommon, -1, -1, 0);

    X509_set_issuer_name(root_ca, root_name);

    const EVP_MD* digest = EVP_sha256();
    X509_sign(root_ca, pkey, digest);

    writeCACert(&root_ca);

    X509_free(root_ca);
    EVP_PKEY_free(pkey);
}

void Certificate::generateRsaKey(EVP_PKEY** pKey)
{
	int error = 0;

	BIGNUM* bne = BN_new();
	error = BN_set_word(bne, RSA_F4);

	RSA* rsa_key = RSA_new();
	error = RSA_generate_key_ex(rsa_key, 2048, bne, NULL);
	*pKey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(*pKey, rsa_key);
	rsa_key = NULL;

	BN_free(bne);
}

void Certificate::writeCertRequest(X509_REQ** request)
{
	int error = 0;

	FILE* fp = fopen(_cert_req_path, "w");
	error = PEM_write_X509_REQ(fp, *request);

	fclose(fp);
}

void Certificate::readCertReqFromFile(unsigned char* buffer) 
{
    FILE* fp = fopen(_cert_req_path, "r");
    if (fp == NULL) throw std::runtime_error(__func__);

    char c;
    int i = 0;
    while ((c = fgetc(fp)) != EOF)
        buffer[i++] = c;

    buffer[i] = '\0';

    fclose(fp);
}

void Certificate::writeCertReqPrivateKey(EVP_PKEY** pKey)
{
	FILE* file = fopen(_cert_req_privateKey_path, "w");

	bool ret = PEM_write_PrivateKey(file, *pKey, NULL, NULL, 0, NULL, NULL);

	fclose(file);
}

void Certificate::writeCertReqPublicKey(EVP_PKEY** pKey)
{
	FILE* file = fopen(_cert_req_publicKey_path, "w");

	bool ret = PEM_write_PUBKEY(file, *pKey);

	fclose(file);
}

void Certificate::writeCertFromRequest(X509** new_cert)
{
    int error = 0;

    FILE* fp = fopen(_new_cert_path, "w");
    PEM_write_X509(fp, *new_cert);
    
    fclose(fp);
}

void Certificate::readCertFromReqFromFile(unsigned char* buffer) 
{
    FILE* fp = fopen(_new_cert_path, "r");
    if (fp == NULL) throw std::runtime_error(__func__);

    char c;
    int i = 0;
    while ((c = fgetc(fp)) != EOF)
        buffer[i++] = c;

    buffer[i] = '\0';

    fclose(fp);
}

void Certificate::generateCertRequest()
{
	int	error = 0;

	X509_REQ* request = X509_REQ_new();
	error = X509_REQ_set_version(request, 1);

	X509_NAME* req_name = X509_REQ_get_subject_name(request);

	error = X509_NAME_add_entry_by_txt(req_name, "C", MBSTRING_ASC,
										(const unsigned char*)_szCountry, -1, -1, 0);
	error = X509_NAME_add_entry_by_txt(req_name, "L", MBSTRING_ASC,
										(const unsigned char*)_szCity, -1, -1, 0);
	error = X509_NAME_add_entry_by_txt(req_name, "O", MBSTRING_ASC,
										(const unsigned char*)_szOrganization, -1, -1, 0);
	error = X509_NAME_add_entry_by_txt(req_name, "CN", MBSTRING_ASC,
										(const unsigned char*)_szCommon, -1, -1, 0);

	EVP_PKEY* pKey = NULL;
	generateRsaKey(&pKey);
	writeCertReqPrivateKey(&pKey);
	writeCertReqPublicKey(&pKey);

	error = X509_REQ_set_pubkey(request, pKey);

    const EVP_MD* digest = EVP_sha256();
	int signature_len = X509_REQ_sign(request, pKey, digest);

	writeCertRequest(&request);

	X509_REQ_free(request);
	EVP_PKEY_free(pKey);
}

void Certificate::generateCertFromRequest()
{
        OpenSSL_add_all_algorithms();

        FILE* fp = NULL;

        fp = fopen(_cert_req_path, "r");
        X509_REQ* cert_req = PEM_read_X509_REQ(fp, NULL, NULL, NULL);
        fclose(fp);

        fp = fopen(_root_ca_path, "r");
        X509* ca_cert = PEM_read_X509(fp, NULL, NULL, NULL);
        fclose(fp);

        EVP_PKEY* ca_privateKey = EVP_PKEY_new();
        fp = fopen(_root_ca_privateKey_path, "r");
		ca_privateKey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
        fclose(fp);

        X509* new_cert = X509_new();
        X509_set_version(new_cert, 1);

        ASN1_INTEGER* aserial = ASN1_INTEGER_new();
        ASN1_INTEGER_set(aserial, 0);
        X509_set_serialNumber(new_cert, aserial);

        X509_NAME* req_name = X509_REQ_get_subject_name(cert_req);
        X509_set_subject_name(new_cert, req_name);

        X509_NAME* root_name = X509_get_subject_name(ca_cert);
        X509_set_issuer_name(new_cert, root_name);

        EVP_PKEY* req_publicKey = X509_REQ_get_pubkey(cert_req);
        X509_REQ_verify(cert_req, req_publicKey);
        X509_set_pubkey(new_cert, req_publicKey);

        X509_gmtime_adj(X509_get_notBefore(new_cert), 0);

        X509_gmtime_adj(X509_get_notAfter(new_cert), 365 * 24 * 60 * 60L);

        X509V3_CTX ctx;
        X509V3_set_ctx(&ctx, ca_cert, new_cert, NULL, NULL, 0);

        const EVP_MD* digest = EVP_sha256();
        X509_sign(new_cert, ca_privateKey, digest);

        writeCertFromRequest(&new_cert);

        EVP_PKEY_free(req_publicKey);
        EVP_PKEY_free(ca_privateKey);
        X509_REQ_free(cert_req);
        X509_free(new_cert);
}
