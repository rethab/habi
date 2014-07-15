{-# LANGUAGE FlexibleInstances #-}
module Habi.Handshake where

import Control.Exception          (try)
import Control.Monad              (when)
import Control.Monad.Trans.Except (ExceptT(..), throwE)
import Control.Monad.Trans.Reader (ReaderT)
import Data.Binary.Put            (Put, putWord8, putWord16be, runPut)
import Data.Binary.Get            (Get, getWord8, getWord16be, runGetOrFail)
import Data.Char                  (chr, ord)
import Data.Word                  (Word16)
import Network.Socket             (Socket)
import Network.Socket.ByteString  (recv, sendAll)

import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS

import Habi.Types

instance SocketMonad (ReaderT CryptoCtx IO) where
    smPut s bs = lift2 SocketException . try $ sendAll s bs
    smGet s n  = lift2 SocketException . try $ recv s n

leecherHandshake :: (SocketMonad m, CryptoMonad m) =>
                     Fpr -> Socket -> ExceptT Error m SessionKey
leecherHandshake lFpr s = do

    -- send fingerprint and get fingerprint
    sFpr <- leecherHello lFpr s

    -- generate and send session key
    sessKey <- genSessKey
    leecherSessionKey sessKey sFpr s

    return sessKey

seederHandshake :: (SocketMonad m, CryptoMonad m) =>
                    Fpr -> Socket -> ExceptT Error m SessionKey
seederHandshake sFpr s = do

    -- send fingerprint and get fingerprint
    _ <- seederHello sFpr s

    -- get session key and acknowledge
    seederAck s

leecherHello :: (SocketMonad m) => Fpr -> Socket -> ExceptT Error m Fpr
leecherHello myFpr s = do
    
    -- send fingerprint
    smPut s (strictPut $ packetID 'L' >> w16beLen myFpr)
    smPut s myFpr

    -- receive fingerprint
    consumeHeader 'S' s
    sFprLen <- consumeLen s
    smGet s (fromIntegral sFprLen)

leecherSessionKey :: (CryptoMonad m, SocketMonad m) =>
                      SessionKey
                   -> Fpr
                   -> Socket
                   -> ExceptT Error m ()
leecherSessionKey sessKey seederFpr s = do
    
    -- encrypt session key
    encSessKey <- asymEncr seederFpr sessKey

    -- send session key
    smPut s (strictPut $ (packetID 'K') >> w16beLen encSessKey)
    smPut s encSessKey

    -- receive ack
    iv <- genIV
    encAckPkg <- smGet s 32
    ackPkg <- symDecr sessKey iv encAckPkg
    expect 'A' ackPkg

    return ()

seederHello :: (SocketMonad m) =>
                Fpr
             -> Socket
             -> ExceptT Error m Fpr
seederHello myFpr s = do
    
    -- receive fingerprint
    consumeHeader 'L' s
    lFprLen <- consumeLen s
    lFpr <- smGet s (fromIntegral lFprLen)

    -- send fingerprint
    smPut s (strictPut $ packetID 'S' >> w16beLen myFpr)
    smPut s myFpr

    return lFpr

seederAck :: (CryptoMonad m, SocketMonad m) =>
              Socket
           -> ExceptT Error m SessionKey
seederAck s = do

    -- receive session key
    consumeHeader 'K' s
    sessKeyLen <- consumeLen s
    encSessKey <- smGet s (fromIntegral sessKeyLen)

    -- decrpyt session key
    sessKey <- asymDecr encSessKey
    
    -- encrypt ack
    iv <- genIV
    encAckPkg <- symEnc sessKey iv (strictPut $ packetID 'A')

    -- send ack
    smPut s encAckPkg

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

consumeHeader :: (SocketMonad m) => Char -> Socket -> ExceptT Error m ()
consumeHeader c s = smGet s 1 >>= runGetE getWord8 >>= expect c . BS.singleton

expect :: (SocketMonad m) => Char -> BS.ByteString -> ExceptT Error m ()
expect c bs
    | BS.null bs = throwE $ OtherError "expected something, got nothing"
    | otherwise  = when (c /= act) (throwE $ UnexpectedPackage c act)
                    where act = chr (fromIntegral $ BS.head bs) 

consumeLen :: (SocketMonad m) => Socket -> ExceptT Error m Word16
consumeLen s = runGetE getWord16be =<< smGet s 2
