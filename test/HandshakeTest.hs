module HandshakeTest (tests) where

import Control.Concurrent
import Control.Monad.Trans.Except
import Control.Monad.Trans.Reader
import Data.Char (ord)
import Network.Socket
import System.Directory
import System.FilePath
import System.Random
import Test.Framework.Providers.HUnit
import Test.Framework.Providers.QuickCheck2
import Test.QuickCheck
import Test.HUnit
import TestUtil

import qualified Control.Monad.State as S (State, runState)
import qualified Data.ByteString     as BS

import Habi.Handshake
import Habi.Types
                      
tests = [ testProperty "leecher_hello" leecher_hello
        , testProperty "seeder_hello" seeder_hello
        , testProperty "leecher_session_key" leecher_session_key
        , testProperty "seeder_ack" seeder_ack
        , testCase     "unexpected_package" unexpected_package
        , testCase     "no_payload" no_payload
        , testCase     "full_handshake_it" full_handshake_it
        , testCase     "expect_but_empty" expect_but_empty
        ]

leecher_hello :: BS.ByteString -> Property
leecher_hello sFpr = BS.length sFpr `between` (1,100) ==>
    let (Right ret, MockState _ w) = runAll fprExchg (newMock sPayload)
    in ret == sFpr && w == lPayload

        where fprExchg = leecherHello lFpr undefined

              sPayload = toPayload 'S' (Just sFpr)

              lFpr = BS.pack [1,2,3,4,5]
              lPayload = toPayload 'L' (Just lFpr)

seeder_hello :: BS.ByteString -> Property
seeder_hello lFpr = BS.length lFpr `between` (1,100) ==>
    let (Right ret, MockState _ w) = runAll fprExchg (newMock lPayload)
    in ret == lFpr && w == sPayload

        where fprExchg = seederHello sFpr undefined

              lPayload = toPayload 'L' (Just lFpr)

              sFpr = BS.pack [1,2,3,4,5]
              sPayload = toPayload 'S' (Just sFpr)

leecher_session_key :: BS.ByteString -> Property
leecher_session_key sessKey = BS.length sessKey `between` (1,100) ==>
    let (Right (), MockState _ w) = runAll skExchg (newMock sPayload)
    in w == lPayload
        where skExchg = leecherSessionKey sessKey lFpr undefined

              sPayload = mock_encr_sync $ toPayload 'A' Nothing

              lFpr = BS.pack [1,2,3,4,5]
              lPayload = toPayload 'K' (Just $ mock_encr_async sessKey)

seeder_ack :: BS.ByteString -> Property
seeder_ack sessKey = BS.length sessKey `between` (1,100) ==>
    let (Right ret, MockState _ w) = runAll skExchg (newMock lPayload)
    in sessKey == ret && w == sPayload
        where skExchg = seederAck undefined

              -- leecher send asym encrypted session key
              lPayload = toPayload 'K' (Just $ mock_encr_async sessKey)

              -- seeder sends sym encrypted acknowledge
              sPayload = mock_encr_sync $ singleton 'A'
              singleton = BS.singleton . fromIntegral . ord

unexpected_package :: Assertion
unexpected_package =
    let (Left (UnexpectedPackage ex ac), MockState _ _) =
                runAll skExchg (newMock lPayload)
    in do ex @?= 'K'
          ac @?= 'U'
        where skExchg = seederAck undefined

              lPayload = toPayload 'U' Nothing

no_payload :: Assertion
no_payload =
    let (Left (DecodeError msg), MockState _ _) =
                runAll skExchg (newMock lPayload)
    in assertBool "" (not $ null msg) -- force eval
        where skExchg = seederAck undefined

              lPayload = BS.empty

expect_but_empty :: Assertion
expect_but_empty =
    do res <- runReaderT (runExceptT (expect 'A' BS.empty))
                         (undefined :: CryptoCtx)
       assertBool "should be left" (isLeft res)
       let err = fromLeft res
       let expected = OtherError undefined
       assertBool "should be other error" (expected ~=~ err)

full_handshake_it :: Assertion
full_handshake_it = do
    filename <- randomString 20
    socketfile <- fmap (</> filename) getTemporaryDirectory

    -- seeder puts session key in here
    sSessHolder <- newEmptyMVar
    -- leecher puts session key in here
    lSessHolder <- newEmptyMVar

    -- seeder must be running before leecher can connect
    sBarrier <- newEmptyMVar

    _ <- forkIO $ runSeeder socketfile sSessHolder sBarrier

    Just _ <- takeMVar' 2000 sBarrier --wait
    _ <- forkIO $ runLeecher socketfile lSessHolder

    Just sSessKey <- takeMVar' 3000 sSessHolder
    Just lSessKey <- takeMVar' 3000 lSessHolder

    -- both end up with the same session key
    sSessKey @?= lSessKey

  where runSeeder socketfile sessHolder barrier = do
          sock <- socket AF_UNIX Stream 0
          bind sock $ SockAddrUnix socketfile
          listen sock 1
          putMVar barrier True
          (conn, _) <- accept sock
          sessKey <- runWithCtx "../h-gpgme/test/bob" $
            seederHandshake bob_pub_fpr conn
          putMVar sessHolder sessKey
          sClose sock
          sClose conn

        runLeecher socketfile sessHolder = do
          sock <- socket AF_UNIX Stream 0
          connect sock $ SockAddrUnix socketfile
          sessKey <- runWithCtx "../h-gpgme/test/alice" $
            leecherHandshake alice_pub_fpr sock
          putMVar sessHolder sessKey
          sClose sock

        runWithCtx homedir act = do
          eres <- runReaderT (runExceptT act) (CryptoCtx homedir)
          case eres of
            Left err -> error (show err)
            Right res -> return res
          
    
-- utilities

toPayload :: Char -> Maybe BS.ByteString -> BS.ByteString
toPayload i mbc = (fromIntegral $ ord i) `BS.cons` contents mbc
    where contents Nothing = BS.empty
          contents (Just c) =
            -- payload length has 16 bit, it is assumed here that
            -- more than 8 bit will not be needed and therefore
            -- the 0 is hardcoded.
            0 `BS.cons` (fromIntegral $ BS.length c) `BS.cons` c

runAll :: ExceptT Error (S.State MockState) a
       -> MockState
       -> (Either Error a, MockState)
runAll = S.runState . runExceptT

randomString :: Int -> IO String
randomString n = (take n . randomRs ('a', 'z')) `fmap` newStdGen

-- try to take mvar again and again for 't' milliseconds
takeMVar' :: Int -> MVar a -> IO (Maybe a)
takeMVar' t mv = go 0
    where go n | n * (t `div` 10) > t = return Nothing
          go n | otherwise = do
            mbv <- tryTakeMVar mv
            case mbv of
                Just v -> return (Just v)
                Nothing -> threadDelay (t * 100) >> go (n+1)
