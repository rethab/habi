module Handshake where

import Control.Monad (when, liftM)
import Data.Binary.Put (putWord8, putWord16be, runPut)
import Data.Binary.Get (getWord8, getWord16be, runGet)
import Data.Char (chr, ord)
import System.IO (Handle)

import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS

data Ctx = Ctx {

    {- fingerprint of this/local party -}
    fpr :: BS.ByteString

} deriving (Show)

-- fingerprint
type Fpr = BS.ByteString

class (Monad m) => HandleMonad m where
    hmPut  :: Handle -> BS.ByteString -> m ()
    hmGet  :: Handle -> Int -> m BS.ByteString

instance HandleMonad IO where
    hmPut  = BS.hPut
    hmGet  = BS.hGet

leecherHello :: (HandleMonad hm) => Ctx -> Handle -> hm Fpr
leecherHello ctx h = do
    
    -- send fingerprint
    hmPut h (LBS.toStrict . runPut $ lPacketID >> lFprLen)
    hmPut h (fpr ctx)

    -- receive fingerprint
    sPacketID <- (runGet getWord8 . LBS.fromStrict) `liftM` hmGet h 1
    sFprLen <- (runGet getWord16be . LBS.fromStrict) `liftM` hmGet h 2
    hmGet h (fromIntegral sFprLen)

  where lFprLen = putWord16be (fromIntegral $ BS.length (fpr ctx))
        lPacketID = putWord8 (fromIntegral $ ord 'L')

seederHello :: (HandleMonad hm) => Ctx -> Handle -> hm Fpr
seederHello ctx h = do
    
    -- receive fingerprint
    lPacketID <- (runGet getWord8 . LBS.fromStrict) `liftM` hmGet h 1
    lFprLen <- (runGet getWord16be . LBS.fromStrict) `liftM` hmGet h 2
    lFpr <- hmGet h (fromIntegral lFprLen)

    -- send fingerprint
    hmPut h (LBS.toStrict . runPut $ sPacketID >> sFprLen)
    hmPut h (fpr ctx)

    return lFpr


  where sFprLen = putWord16be (fromIntegral $ BS.length (fpr ctx))
        sPacketID = putWord8 (fromIntegral $ ord 'S')
