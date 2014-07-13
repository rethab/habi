module Habi.Types where

import Control.Exception          (SomeException)
import Control.Monad.Trans        (lift)
import Control.Monad.Trans.Except (ExceptT(..))
import Control.Monad.Trans.Reader (ReaderT(..))
import System.IO                  (Handle)

import qualified Crypto.Cipher   as C
import qualified Data.ByteString as BS

-- fingerprint
type Fpr = BS.ByteString

type SessionKey = BS.ByteString

type Plain = BS.ByteString

type Encrypted = BS.ByteString

newtype IV = IV (C.IV C.AES256)

data Error =
      -- package 'exp' was expected, but 'act' was received
      UnexpectedPackage { _exp :: Char, _act :: Char }

      -- exception from operation on handle
    | HandleException { _exc :: SomeException }

      -- error while decoding binary
    | DecodeError { _msg :: String }

      -- error from underlying crypto module
    | CryptoError { _cause :: String }

      -- other generic error
    | OtherError { _reason :: String }
    deriving (Show)

class (Monad m) => CryptoMonad m where
    asymEncr   :: Fpr -> Plain -> ExceptT Error m Encrypted
    asymDecr   :: Encrypted -> ExceptT Error m Plain
    symEnc     :: SessionKey -> IV -> Plain -> ExceptT Error m Encrypted
    symDecr    :: SessionKey -> IV -> Encrypted -> ExceptT Error m Plain
    genSessKey :: ExceptT Error m SessionKey
    genIV      :: ExceptT Error m IV

class (Monad m) => HandleMonad m where
    hmPut :: Handle -> BS.ByteString -> ExceptT Error m ()
    hmGet :: Handle -> Int -> ExceptT Error m BS.ByteString

data CryptoCtx = CryptoCtx {
      -- homedir of gpg
      gpgDir :: String
}

mapLeft :: (e -> Error) -> Either e a -> Either Error a
mapLeft f (Left v)  = Left (f v)
mapLeft _ (Right v) = Right v

lift2 :: (e -> Error) -> IO (Either e a) -> ExceptT Error (ReaderT CryptoCtx IO) a
lift2 eTrans act = ExceptT . lift $ mapLeft eTrans `fmap` act
