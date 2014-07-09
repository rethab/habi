module HandshakeTest (tests) where

import Control.Concurrent
import Control.Monad.Trans.Except
import Control.Monad.Trans.Reader
import Data.Char (ord)
import Data.Maybe
import Network.Socket
import System.Directory
import System.FilePath
import System.IO
import Test.Framework.Providers.HUnit
import Test.Framework.Providers.QuickCheck2
import Test.QuickCheck
import Test.HUnit
import TestUtil

import qualified Control.Monad.State as S (State, runState)
import qualified Data.ByteString     as BS

import Crypto
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

full_handshake_it = do
    socketfile <- fmap (</> "habi.socket") getTemporaryDirectory

    -- seeder puts session key in here
    sSessHolder <- newEmptyMVar
    -- leecher puts session key in here
    lSessHolder <- newEmptyMVar

    -- seeder must be running before leecher can connect
    sBarrier <- newEmptyMVar

    forkIO $ runSeeder socketfile sSessHolder sBarrier

    _ <- takeMVar sBarrier --wait
    forkIO $ runLeecher socketfile lSessHolder

    sSessKey <- takeMVar sSessHolder
    lSessKey <- takeMVar lSessHolder

    -- both end up with the same session key
    sSessKey @?= lSessKey

  where runSeeder socketfile sessHolder barrier = do
          sock <- socket AF_UNIX Stream 0
          listen sock 1
          putMVar barrier True
          (conn, _) <- accept sock
          h <- socketToHandle conn ReadWriteMode
          Right sessKey <- runWithCtx "" $ seederHandshake bob_pub_fpr h
          putMVar sessHolder sessKey
          sClose sock
          sClose conn

        runLeecher socketfile sessHolder = do
          sock <- socket AF_UNIX Stream 0
          connect sock $ SockAddrUnix socketfile
          h <- socketToHandle sock ReadWriteMode
          Right sessKey <- runWithCtx "" $ leecherHandshake bob_pub_fpr h
          putMVar sessHolder sessKey
          sClose sock

        runWithCtx gpgDir act = 
          runReaderT (runExceptT act) (CryptoCtx gpgDir)
          
    
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
