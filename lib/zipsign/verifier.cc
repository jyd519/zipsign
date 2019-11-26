#include "zipsign/verifier.hpp"
#include "zipsign/zip.hpp"
#include "zipsign/partial_input_file.hpp"
#include "zipsign/signature.hpp"

#include <iostream>

using openssl::Certificate;
using openssl::CertificateStore;
using openssl::CertificateStack;
using openssl::CMS;

namespace zipsign
{

Verifier::Verifier(std::string const & cert_file)
: cert(Certificate::fromPEM(cert_file))
{

}

Verifier::~Verifier()
{

}

bool Verifier::verify(std::string const & filename, bool is_verbose)
{
    bool result = false;

    try
    {
        Zip zip(filename);

        auto commentSize = zip.getCommentStart();
        PartialInputFile partialFile;
        auto file = partialFile.open(filename, commentSize);

        auto comment = zip.getComment();
        if (0 != comment.find(ZIPSIGN_SIGNATURE_PREFIX))
        {
            throw std::runtime_error("missing signature");
        }
        auto signature = comment.substr(std::string(ZIPSIGN_SIGNATURE_PREFIX).size());

        CertificateStore store;
        store.add(cert);

        CertificateStack certs;
        certs.push(cert);

        auto cms = CMS::fromBase64(signature);
        result = cms.verify(certs, store, file, nullptr,  CMS_DETACHED | CMS_BINARY ,is_verbose);
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