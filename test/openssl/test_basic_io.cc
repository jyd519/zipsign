#include <gtest/gtest.h>
#include <openssl++/basic_io.hpp>
#include <openssl++/exception.hpp>

using openssl::BasicIO;

TEST(BasicIO, OpenInputFile)
{
    BasicIO file = BasicIO::openInputFile("test.zip");
}

TEST(BasicIO, Fail_OpenInputFile_NotExists)
{
    ASSERT_THROW({
        BasicIO::openInputFile("non-existing-test.zip");
    },
    openssl::FileNotFoundException);
}

TEST(BasicIO, FromMemory)
{
    BasicIO bio = BasicIO::fromMemory();
}

TEST(BasicIO, MoveConstuctible)
{
    BasicIO bio = BasicIO::fromMemory();
    BasicIO x = std::move(bio);

    ASSERT_EQ(nullptr, static_cast<BIO*>(bio));
    ASSERT_NE(nullptr, static_cast<BIO*>(x));
}

TEST(BasicIO, MoveAssignable)
{
    BasicIO bio = BasicIO::fromMemory();
    BasicIO x = BasicIO::fromMemory();
    x = std::move(bio);

    ASSERT_EQ(nullptr, static_cast<BIO*>(bio));
    ASSERT_NE(nullptr, static_cast<BIO*>(x));
}