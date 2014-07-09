module Handshake where

import Control.Exception (try)
import Control.Monad (when)
import Control.Monad.Trans.Except (ExceptT(..), throwE, withExceptT)
import Data.Binary.Put (Put, putWord8, putWord16be, runPut)
import Data.Binary.Get (Get, getWord8, getWord16be, runGetOrFail)
import Data.Char (chr, ord)
import Data.Word (Word16)
import System.IO (Handle)

import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS

import Crypto
import Types


class (Monad m) => HandleMonad m where
    hmPut  :: Handle -> BS.ByteString -> ExceptT Error m ()
    hmGet  :: Handle -> Int -> ExceptT Error m BS.ByteString

instance HandleMonad IO where
    hmPut h bs = mapException $ BS.hPut h bs
    hmGet h n = mapException $ BS.hGet h n

leecherHandshake (HandleMonad m, CryptoMonad m) =>
                    Fpr -> Handle -> ExceptT Error m SessionKey
leecherHandshake lFpr h = do

    -- send fingerprint and get fingerprint
    sFpr <- leecherHello lFpr h

    -- send session key
    sessKey <- genSessKey
    leecherSessionKey sessKey sFpr h

seederHandshake (HandleMonad m, CryptoMonad m) =>
                    Fpr -> Handle -> ExceptT Error m SessionKey
seederHandshake sFpr h = do

    -- send fingerprint and get fingerprint
    sFpr <- seederHello lFpr h

    -- get session key and acknowledge
    seederAck h

leecherHello :: (HandleMonad m) => Fpr -> Handle -> ExceptT Error m Fpr
leecherHello myFpr h = do
    
    -- send fingerprint
    hmPut h (strictPut $ packetID 'L' >> w16beLen myFpr)
    hmPut h myFpr

    -- receive fingerprint
    consumeHeader 'S' h
    sFprLen <- consumeLen h
    hmGet h (fromIntegral sFprLen)

leecherSessionKey :: (CryptoMonad m, HandleMonad m) =>
                      SessionKey
                   -> Fpr
                   -> Handle
                   -> ExceptT Error m ()
leecherSessionKey sessKey seederFpr h = do
    
    -- encrypt session key
    encSessKey <- asymFor seederFpr sessKey

    -- send session key
    hmPut h (strictPut $ (packetID 'K') >> w16beLen encSessKey)
    hmPut h encSessKey

    -- receive ack
    consumeHeader 'A' h

    return ()

seederHello :: (HandleMonad m) =>
                Fpr
             -> Handle
             -> ExceptT Error m Fpr
seederHello myFpr h = do
    
    -- receive fingerprint
    consumeHeader 'L' h
    lFprLen <- consumeLen h
    lFpr <- hmGet h (fromIntegral lFprLen)

    -- send fingerprint
    hmPut h (strictPut $ packetID 'S' >> w16beLen myFpr)
    hmPut h myFpr

    return lFpr

seederAck :: (CryptoMonad m, HandleMonad m) =>
              Handle
           -> ExceptT Error m SessionKey
seederAck h = do

    -- receive session key
    consumeHeader 'K' h
    sessKeyLen <- consumeLen h
    encSessKey <- hmGet h (fromIntegral sessKeyLen)

    -- decrpyt session key
    sessKey <- asymDecr encSessKey
    
    -- encrypt session key
    encAckPkg <- symEnc sessKey (strictPut $ packetID 'A')

    -- send session key
    hmPut h encAckPkg

    return sessKey

packetID :: Char -> Put
packetID = putWord8 . fromIntegral . ord

w16beLen :: BS.ByteString -> Put
w16beLen = putWord16be . fromIntegral . BS.length

strictPut :: Put -> BS.ByteString
strictPut = LBS.toStrict . runPut

runGetE :: (Monad m) => Get a -> BS.ByteString -> ExceptT Error m a
runGetE g bs = ExceptT . return $ runGet g bs

runGet :: Get a -> BS.ByteString -> Either Error a
runGet g = mapEither . runGetOrFail g . LBS.fromStrict
    where mapEither (Left l) = Left (DecodeError $ thrd l)
          mapEither (Right r) = Right (thrd r)
          thrd (_,_,x) = x

consumeHeader :: (HandleMonad m) => Char -> Handle -> ExceptT Error m ()
consumeHeader c h = hmGet h 1 >>= runGetE getWord8 >>= expect
    where expect w = when (c /= act) (throwE $ UnexpectedPackage c act)
            where act = chr (fromIntegral w) 

consumeLen :: (HandleMonad m) => Handle -> ExceptT Error m Word16
consumeLen h = runGetE getWord16be =<< hmGet h 2
