/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "zipsign/verifier.hpp"
#include "zipsign/partial_input_file.hpp"
#include "zipsign/signature.hpp"
#include "zipsign/zip.hpp"

#include <iostream>
#include <stdexcept>

using openssl::Certificate;
using openssl::CertificateStack;
using openssl::CertificateStore;
using openssl::CMS;

namespace zipsign {

const char kJoyTestRootCert[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDljCCAn4CCQCSVJ2KU6akEjANBgkqhkiG9w0BAQsFADCBjDELMAkGA1UEBhMC\n"
    "Q04xETAPBgNVBAgMCFNoYW5naGFpMREwDwYDVQQHDAhTaGFuZ2hhaTEMMAoGA1UE\n"
    "CgwDYXRhMQwwCgYDVQQLDANkZXYxFTATBgNVBAMMDEpveVRlc3QgUm9vdDEkMCIG\n"
    "CSqGSIb3DQEJARYVaml5b25nZG9uZ0BhdGEubmV0LmNuMB4XDTEwMDEwMTA2MTUz\n"
    "MFoXDTM5MTIyNTA2MTUzMFowgYwxCzAJBgNVBAYTAkNOMREwDwYDVQQIDAhTaGFu\n"
    "Z2hhaTERMA8GA1UEBwwIU2hhbmdoYWkxDDAKBgNVBAoMA2F0YTEMMAoGA1UECwwD\n"
    "ZGV2MRUwEwYDVQQDDAxKb3lUZXN0IFJvb3QxJDAiBgkqhkiG9w0BCQEWFWppeW9u\n"
    "Z2RvbmdAYXRhLm5ldC5jbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\n"
    "AON/SnUadNW+k6wlT1hNkPgHL6E3zeL6yZT49koWRIzsH2JFEFdLs1WORtbefs+y\n"
    "ZXF1dq200/tQBA1iSvt4bkokAghEb6lQUl3RyuxzRtye4Q8Y6f8ZFw1W1LO1/VU9\n"
    "kThYi4uRblYiSN35t5S0CVodNPteetG+TZ06kIP+VI5lMSy4nSvSqPBjkVOKOBaV\n"
    "0rpOI9MZ7J8W7LVz5swAr4JH51hrCzaX9zDJqGhSHxjWdPyTje208vD55OpgAqLi\n"
    "8Z2Npp8hgoIrRuXyJGagUOm0tSr35ZaqqYIca+m59ZBVtA9xOa7rfJ5OjYqRaU8g\n"
    "LI18IHREdUQF1QszPgkUNkkCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEA3Nt1B9wt\n"
    "sSdVNSfnXq4fBB5EGxTxKoHaevOFpynFaP8X8zZ3vci41b8eb389MocoJrr/cwU9\n"
    "ikkfm19zLQmkkWEhRSGlMTEm1w1H3zgNJSJrquTkaMYIVvVoNx3Wkd7MZ6ei0vSl\n"
    "8J8isDVq47wc2YO5ZDQByrIaTiBtUCZ3gkvjeIpxjcVfSwAgxhl/nB3+5SAHeP3j\n"
    "VbNDy8JQtCviYOGzaUQFxW3s12m81rHlx6Ohmm6ksm4rQVmuo++w08GY7tmtC0yw\n"
    "gAwDjP5t5uhfFd4fb2tn6nZEvZKAmkhfn66a9v+mEPipAEagmxcfJ5/eooUJBOYv\n"
    "MEbNMDiZKXNRMw==\n"
    "-----END CERTIFICATE-----";

Verifier::Verifier(std::string const& cert_file) { addCertificate(cert_file); }

Verifier::~Verifier() {}

void Verifier::addCertificateData(std::string const& pem) {
  signers.push_back(Certificate::fromPEMData(pem.data(), pem.size()));
}

void Verifier::addCertificate(std::string const& filename) {
  signers.push_back(Certificate::fromPEM(filename));
}

Verifier::Result Verifier::verify(
    std::string const & filename,
    std::string const & keyring_path,
    bool is_verbose,
    bool is_self_signed)
{
    Result result = Bad;

    try
    {
        Zip zip(filename);

        auto commentSize = zip.getCommentStart();
        PartialInputFile partialFile;
        auto file = partialFile.open(filename, commentSize);

        auto comment = zip.getComment();
        if (0 != comment.find(ZIPSIGN_SIGNATURE_PREFIX))
        {
            result = BadMissingSignature;
            throw std::runtime_error("missing signature");
        }
        auto signature = comment.substr(std::string(ZIPSIGN_SIGNATURE_PREFIX).size());

        CertificateStore store;
        if (!keyring_path.empty())
        {
            store.loadFromFile(keyring_path);
        }
        CertificateStack certs;

        for(auto & cert: signers)
        {
            store.add(cert);
            certs.push(cert);
        }

        auto cms = CMS::fromBase64(signature);

        for (auto & cert: signers)
        {
            STACK_OF(X509) * untrusted = cms.getCerts();
            if (!is_self_signed && !cert.verify(store, nullptr, untrusted))
            {
                sk_X509_pop_free(untrusted, X509_free);
                result = BadInvalidCertificateChain;
                throw std::runtime_error("signers certificate is not valid");
            }
            sk_X509_pop_free(untrusted, X509_free);
        }

        auto const chain_valid = cms.verify(certs, store, file, nullptr,  CMS_DETACHED | CMS_BINARY | CMS_NO_SIGNER_CERT_VERIFY | CMS_NO_CONTENT_VERIFY, is_verbose);
        if (!chain_valid)
        {
            result = BadInvalidCertificateChain;
            throw std::runtime_error("certificate chain is not valid");
        }

        file = partialFile.open(filename, commentSize);
        auto const valid = cms.verify(certs, store, file, nullptr,  CMS_DETACHED | CMS_BINARY | CMS_NO_SIGNER_CERT_VERIFY, is_verbose);
        result = valid ? Good : BadInvalidSignature;
    }
    catch(const std::exception& ex)
    {
        if (is_verbose)
        {
            std::cerr << "error: " << ex.what() << std::endl;
        }
    }    

    return result;
}

}