{-# LANGUAGE FlexibleInstances #-}
module Crypto where

import Control.Monad (replicateM)
import Control.Monad.Trans (lift)
import Control.Monad.Trans.Except (ExceptT(..))
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

lift2 :: (e -> Error)
     -> IO (Either e a)
     -> ExceptT Error (ReaderT CryptoCtx IO) a
lift2 eTrans act = ExceptT . lift $ mapLeft eTrans `fmap` act

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
    symEnc key plain = do
        ctx <- lift2 CryptoError $ initAES256 key
        iv <- lift2 CryptoError genIV
        return $ cbcEncrypt ctx iv plain

    -- sym decryption with cryptocipher
    symEnc key cipher = do
        ctx <- lift2 CryptoError $ initAES256 key
        iv <- lift2 CryptoError genIV
        return $ cbcDecrypt ctx iv cipher

    genSessKey = lift2 CryptoError $ (Right . BS.pack) `fmap` replicateM 32 randomIO

genIV :: IO (Either String (IV AES256))
genIV = (maybe (Left "invalid iv") Right . makeIV) `fmap` ivBS
    where ivBS = BS.pack `fmap` replicateM 16 randomIO

initAES256 :: BS.ByteString -> IO (Either String AES256)
initAES256 key = return . showLeft $ cipherInit `fmap` makeKey key
  where showLeft (Left err) = Left (show err)
        showLeft (Right r)  = Right r
