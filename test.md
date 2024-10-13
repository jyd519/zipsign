```sh
 ./build/zipsign sign -f test.zip -p ../joytest_pki/joytest/joytest.key -c ../joytest_pki/joytest/joytest.pem -i ../joytest_pki/signing-ca.pem -e -v

 ./build/zipsign info -f test.zip
 ./build/zipsign verify -f test.zip -c ../joytest_pki/ca.pem
```
