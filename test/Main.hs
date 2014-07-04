import Test.Framework (defaultMain, testGroup)

import HandshakeTest

main = defaultMain
    [ testGroup "handshake" HandshakeTest.tests
    ]
