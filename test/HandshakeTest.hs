module HandshakeTest (tests) where

import Control.Monad.State (State, runState)
import Control.Monad.Trans.Except (ExceptT(..), runExceptT)
import qualified Data.ByteString as BS
import Data.Char (ord)
import Data.Knob
import Data.Maybe
import System.IO
import Test.Framework.Providers.HUnit
import Test.Framework.Providers.QuickCheck2
import Test.QuickCheck
import TestUtil

import Handshake
import Types
                      
tests = [ testProperty "leecher_hello" leecher_hello
        , testProperty "seeder_hello" seeder_hello
        --, testProperty "leecher_session_key" leecher_session_key
        --, testCase "decrypt_garbage" decrypt_garbage
        ]

leecher_hello sFpr = BS.length sFpr `between` (1,100) ==>
    let (Right ret, MockState _ w) = runAll fprExchg (newMock sPayload)
    in ret == sFpr && w == lPayload

        where fprExchg = leecherHello lFpr undefined

              sPayload = toPayload 'S' sFpr

              lFpr = BS.pack [1,2,3,4,5]
              lPayload = toPayload 'L' lFpr

              toPayload :: Char -> BS.ByteString -> BS.ByteString
              toPayload i f = BS.pack [ fromIntegral $ ord i
                                      , 0
                                      , fromIntegral $ BS.length f ]
                              `BS.append` f

seeder_hello lFpr = BS.length lFpr `between` (1,100) ==>
    let (Right ret, MockState _ w) = runAll fprExchg (newMock lPayload)
    in ret == lFpr && w == sPayload

        where fprExchg = seederHello sFpr undefined

              lPayload = toPayload 'L' lFpr

              sFpr = BS.pack [1,2,3,4,5]
              sPayload = toPayload 'S' sFpr

              toPayload :: Char -> BS.ByteString -> BS.ByteString
              toPayload i f = BS.pack [ fromIntegral $ ord i
                                      , 0
                                      , fromIntegral $ BS.length f ]
                              `BS.append` f

runAll :: ExceptT Error (State MockState) a
       -> MockState
       -> (Either Error a, MockState)
runAll = runState . runExceptT
