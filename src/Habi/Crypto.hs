{-# LANGUAGE FlexibleInstances #-}
module Habi.Crypto where

import Control.Monad              (replicateM)
import Control.Monad.Trans        (lift)
import Control.Monad.Trans.Except (ExceptT(..))
import Control.Monad.Trans.Reader (ReaderT, ask)
import Crypto.Gpgme               (encryptSign', decryptVerify')
import Data.Word                  (Word8)
import System.Random              (randomIO)

import qualified Crypto.Cipher   as C
import qualified Data.ByteString as BS

import Habi.Types

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
    symEnc key iv plain = lift2 CryptoError $ symmetricEncrypt key iv plain

    -- sym decryption with cryptocipher
    symDecr key iv cipher = lift2 CryptoError $ symmetricDecrypt key iv cipher

    genSessKey = ExceptT . lift $ Right `fmap` randomSessionKey

    genIV = return newIV

symmetricEncrypt :: SessionKey -> IV -> Plain -> IO (Either String Encrypted)
symmetricEncrypt key (IV iv) plain = do
    ectx <- initAES256 key
    return $ ectx >>= \ctx -> Right $ C.cbcEncrypt ctx iv (pad 32 plain)

symmetricDecrypt :: SessionKey -> IV -> Encrypted -> IO (Either String Plain)
symmetricDecrypt key (IV iv) cipher = do
    ectx <- initAES256 key
    return $ ectx >>= \ctx -> Right (unpad $ C.cbcDecrypt ctx iv cipher)

randomSessionKey :: IO SessionKey
randomSessionKey = BS.pack `fmap` replicateM 32 randomIO

newIV :: IV
newIV = IV C.nullIV

incrementIV :: IV -> IV
incrementIV (IV iv) = IV (C.ivAdd iv 1)

pad :: Word8 -> BS.ByteString -> BS.ByteString
pad len bs = bs `BS.append` BS.replicate (fromIntegral padLen) padLen
    where -- number of bytes to be appended
          padLen :: Word8
          padLen = len - overlaps

          -- bytes in next block
          overlaps = fromIntegral (BS.length bs `mod` fromIntegral len)

unpad :: BS.ByteString -> BS.ByteString
unpad bs | BS.null bs = BS.empty
         | otherwise  = fst $ BS.splitAt idxRight bs
    where idxRight = BS.length bs - fromIntegral (BS.last bs)

initAES256 :: BS.ByteString -> IO (Either String C.AES256)
initAES256 key = return . showLeft $ C.cipherInit `fmap` C.makeKey key
  where showLeft (Left err) = Left (show err)
        showLeft (Right r)  = Right r
