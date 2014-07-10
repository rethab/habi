module TestMain where

import Test.Framework (defaultMain, testGroup)

import HandshakeTest
import CryptoTest

main :: IO ()
main = defaultMain
    [ testGroup "handshake" HandshakeTest.tests
    , testGroup "crypto" CryptoTest.tests
    ]
