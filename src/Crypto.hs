{-# LANGUAGE FlexibleInstances #-}
module Crypto where

import Control.Monad              (replicateM)
import Control.Monad.Trans        (lift)
import Control.Monad.Trans.Reader (ReaderT, ask)
import Crypto.Gpgme               (encryptSign', decryptVerify')
import Data.Word                  (Word8)
import System.Random              (randomIO)

import qualified Crypto.Cipher   as C
import qualified Data.ByteString as BS

import Types

instance CryptoMonad (ReaderT CryptoCtx IO) where

    -- asym encryption with gpgme
    asymEncr recFpr plain = do
        ctx <- lift ask
        lift2 CryptoError $ encryptSign' (gpgDir ctx) recFpr plain

    -- asym decryption with gpgme
    asymDecr cipher = do
        ctx <- lift ask
        lift2 (CryptoError . show) $ decryptVerify' (gpgDir ctx) cipher

    -- sym encryption with cryptocipher
    symEnc key (IV iv) plain = do
        ctx <- lift2 CryptoError $ initAES256 key
        return $ C.cbcEncrypt ctx iv (pad 32 plain)

    -- sym decryption with cryptocipher
    symDecr key (IV iv) cipher = do
        ctx <- lift2 CryptoError $ initAES256 key
        return . unpad $ C.cbcDecrypt ctx iv cipher

    genSessKey = lift2 CryptoError $ Right `fmap` genRand 32

    genIV = return $ IV C.nullIV

pad :: Word8 -> BS.ByteString -> BS.ByteString
pad len bs = bs `BS.append` (BS.replicate (fromIntegral padLen) padLen)
    where -- number of bytes to be appended
          padLen :: Word8
          padLen = let padLen' = len - overlaps
                   in if padLen' == 0 then len else padLen'

          -- bytes in next block
          overlaps = fromIntegral (BS.length bs `mod` fromIntegral len)

unpad :: BS.ByteString -> BS.ByteString
unpad bs | BS.null bs = BS.empty
         | otherwise  = fst $ BS.splitAt idxRight bs
    where idxRight = BS.length bs - (fromIntegral $ BS.last bs)

genRand :: Int -> IO BS.ByteString
genRand n = BS.pack `fmap` replicateM n randomIO

initAES256 :: BS.ByteString -> IO (Either String C.AES256)
initAES256 key = return . showLeft $ C.cipherInit `fmap` C.makeKey key
  where showLeft (Left err) = Left (show err)
        showLeft (Right r)  = Right r
