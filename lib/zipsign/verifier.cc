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

static const char kNewJoyTestRoot[] = "-----BEGIN CERTIFICATE-----\n"
"MIIEUDCCAzigAwIBAgIBAjANBgkqhkiG9w0BAQsFADB4MRUwEwYDVQQDDAxKb3lU\n"
"ZXN0IFJvb3QxETAPBgNVBAgMCFNoYW5naGFpMQswCQYDVQQGEwJDTjEkMCIGCSqG\n"
"SIb3DQEJARYVaml5b25nZG9uZ0BhdGEubmV0LmNuMQwwCgYDVQQKDANhdGExCzAJ\n"
"BgNVBAsMAlJEMCAXDTEwMDEwMTAwMDAwMFoYDzIxMDQwODAyMTIxMDI1WjB4MRUw\n"
"EwYDVQQDDAxKb3lUZXN0IFJvb3QxETAPBgNVBAgMCFNoYW5naGFpMQswCQYDVQQG\n"
"EwJDTjEkMCIGCSqGSIb3DQEJARYVaml5b25nZG9uZ0BhdGEubmV0LmNuMQwwCgYD\n"
"VQQKDANhdGExCzAJBgNVBAsMAlJEMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\n"
"CgKCAQEA0YZekG6LB+uk0QbtR7Onu+feuQFr641pc0i+ITaJxf8mXt6P94v83RMy\n"
"wS2IM5KFFRfwBRN/3ZZfuZbt5vNELMWmeUPhin2lLV2oB2oz5xPW5Vpy4ZacKaW+\n"
"th2eIN7um8zglf3c3+n0QhshBb2BkM0xzTGbMzfzONFAdBGBKxTeDrQw1u3EXI9I\n"
"EAjkB0Nz/pq54bwr1pMfhTO/VGjXUFywm5VOfGR1ZMkgi1zhuzq0VbGpWS+9eh3o\n"
"mKdhdvFdHdBmcf0H9HKapTZ9n+fHPhIBpeodNnN7EySKGjWGl1y5lxRcJf1kD12i\n"
"2nlMayRm0DVHgq470y+aYXXPhTOJUwIDAQABo4HiMIHfMB0GA1UdDgQWBBSQAGqz\n"
"dC4VrOXLrMDGTtYI8RBk3zCBogYDVR0jBIGaMIGXgBSQAGqzdC4VrOXLrMDGTtYI\n"
"8RBk36F8pHoweDEVMBMGA1UEAwwMSm95VGVzdCBSb290MREwDwYDVQQIDAhTaGFu\n"
"Z2hhaTELMAkGA1UEBhMCQ04xJDAiBgkqhkiG9w0BCQEWFWppeW9uZ2RvbmdAYXRh\n"
"Lm5ldC5jbjEMMAoGA1UECgwDYXRhMQswCQYDVQQLDAJSRIIBAjAMBgNVHRMEBTAD\n"
"AQH/MAsGA1UdDwQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEAjUnRVbr7F+Y5QWIW\n"
"1QIdFSPKopl25ECPon3HcLoxw3YfMXgI901iAVXmf+O0up3pHQZiMHy92wJ5XYGJ\n"
"6cUZEIjif92x7vDx9uIcqh7GTviBw8PC7kTAWBygVrgW+8lSPaohmrQicpfGvVrJ\n"
"q/GkG2FMTYR+qA61877eQx5enMUePyxGfb/I9RdIVXnb4wsb7fzFZR+alFdqe0/B\n"
"9F7hc06umitmVKveGeO3fHqaaqoBmSXsCywF9ySoqEFAi2iYEfPlXj1nikYvS4lg\n"
"dCi6u9Skp16TIxBGNpB+K6hIUBbHQUeh3cqW6WGXxmw+OOuTPMo5wNTulQxnW4DR\n"
"7HMOag==\n"
"-----END CERTIFICATE-----\n";

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
        addCertificateData(kJoyTestRootCert);
        addCertificateData(kNewJoyTestRoot);

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
