{-# LANGUAGE FlexibleInstances #-}
module Crypto where

import Control.Monad (replicateM)
import Control.Monad.Trans (lift)
import Control.Monad.Trans.Except (ExceptT)
import Control.Monad.Trans.Reader (ReaderT, ask)
import Crypto.Cipher (IV, AES256, cipherInit, makeIV, makeKey)
import Crypto.Cipher (cbcDecrypt, cbcEncrypt)
import Crypto.Gpgme (encryptSign', decryptVerify')
import System.Random (randomIO)

import qualified Data.ByteString as BS

import Types

class (Monad m) => CryptoMonad m where
    asymEncr   :: Fpr -> Plain -> ExceptT Error m Encrypted
    asymDecr   :: Encrypted -> ExceptT Error m Plain
    symEnc     :: SessionKey -> Plain -> ExceptT Error m Encrypted
    symDecr    :: SessionKey -> Encrypted -> ExceptT Error m Plain
    genSessKey :: ExceptT Error m SessionKey

data CryptoCtx = CryptoCtx {
      -- homedir of gpg
      gpgDir :: String
}

instance CryptoMonad (ReaderT CryptoCtx IO) where

    -- asym encryption with gpgme
    asymEncr recFpr plain = lift ask >>= \ctx ->
        mapException $ encryptSign' (gpgDir ctx) recFpr plain

    -- asym decryption with gpgme
    asymDecr cipher = ask >>= \ctx ->
        mapException $ decryptVerify' (gpgDir ctx) cipher

    -- sym encryption with cryptocipher
    symEnc key plain = do
        ctx <- initAES256 key
        iv <- genIV
        cbcEncrypt ctx iv plain

    -- sym decryption with cryptocipher
    symEnc key cipher = do
        ctx <- initAES256 key
        iv <- genIV
        cbcDecrypt ctx iv cipher

    genSessKey = BS.pack `fmap` replicateM 32 randomIO

genIV :: IO (Either String (IV AES256))
genIV = (maybe (Left "invalid iv") Right . makeIV) `fmap` ivBS
    where ivBS = BS.pack `fmap` replicateM 16 randomIO

initAES256 :: BS.ByteString -> IO (Either String AES256)
initAES256 key = return . showLeft $ cipherInit `fmap` makeKey key
  where showLeft (Left err) = Left (show err)
        showLeft (Right r)  = Right r
