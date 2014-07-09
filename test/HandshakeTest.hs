module HandshakeTest (tests) where

import qualified Control.Monad.State as S (State, runState)
import Control.Monad.Trans.Except (ExceptT(..), runExceptT)
import qualified Data.ByteString as BS
import Data.Char (ord)
import Data.Maybe
import System.IO
import Test.Framework.Providers.HUnit
import Test.Framework.Providers.QuickCheck2
import Test.QuickCheck
import Test.HUnit
import TestUtil

import Handshake
import Types
                      
tests = [ testProperty "leecher_hello" leecher_hello
        , testProperty "seeder_hello" seeder_hello
        , testProperty "leecher_session_key" leecher_session_key
        , testProperty "seeder_ack" seeder_ack
        , testCase     "unexpected_package" unexpected_package
        , testCase     "no_payload" no_payload
        , testCase     "full_handshake_it" full_handshake_it
        ]

leecher_hello sFpr = BS.length sFpr `between` (1,100) ==>
    let (Right ret, MockState _ w) = runAll fprExchg (newMock sPayload)
    in ret == sFpr && w == lPayload

        where fprExchg = leecherHello lFpr undefined

              sPayload = toPayload 'S' (Just sFpr)

              lFpr = BS.pack [1,2,3,4,5]
              lPayload = toPayload 'L' (Just lFpr)

seeder_hello lFpr = BS.length lFpr `between` (1,100) ==>
    let (Right ret, MockState _ w) = runAll fprExchg (newMock lPayload)
    in ret == lFpr && w == sPayload

        where fprExchg = seederHello sFpr undefined

              lPayload = toPayload 'L' (Just lFpr)

              sFpr = BS.pack [1,2,3,4,5]
              sPayload = toPayload 'S' (Just sFpr)

leecher_session_key sessKey = BS.length sessKey `between` (1,100) ==>
    let (Right (), MockState _ w) = runAll skExchg (newMock sPayload)
    in w == lPayload
        where skExchg = leecherSessionKey sessKey lFpr undefined

              sPayload = toPayload 'A' Nothing

              lFpr = BS.pack [1,2,3,4,5]
              lPayload = toPayload 'K' (Just $ mock_encr_async sessKey)

seeder_ack sessKey = BS.length sessKey `between` (1,100) ==>
    let (Right ret, MockState _ w) = runAll skExchg (newMock lPayload)
    in sessKey == ret && w == sPayload
        where skExchg = seederAck undefined

              lPayload = toPayload 'K' (Just $ mock_encr_async sessKey)

              sPayload = mock_encr_sync (BS.singleton . fromIntegral $ ord 'A')

unexpected_package =
    let (Left (UnexpectedPackage ex ac), MockState _ _) =
                runAll skExchg (newMock lPayload)
    in do ex @?= 'K'
          ac @?= 'U'
        where skExchg = seederAck undefined

              lPayload = toPayload 'U' Nothing

no_payload =
    let (Left (DecodeError msg), MockState _ _) =
                runAll skExchg (newMock lPayload)
    in assertBool "" (not $ null msg) -- force eval
        where skExchg = seederAck undefined

              lPayload = BS.empty

full_handshake_it = 



-- utilities

toPayload :: Char -> Maybe BS.ByteString -> BS.ByteString
toPayload i mbc = (fromIntegral $ ord i) `BS.cons` contents mbc
    where contents Nothing = BS.empty
          contents (Just c) =
            0 `BS.cons` (fromIntegral $ BS.length c) `BS.cons` c

runAll :: ExceptT Error (S.State MockState) a
       -> MockState
       -> (Either Error a, MockState)
runAll = S.runState . runExceptT
