module Types where

import Control.Exception (SomeException, try)
import Control.Monad.Trans.Except (ExceptT(..), withExceptT)
import qualified Data.ByteString as BS

-- fingerprint
type Fpr = BS.ByteString

type SessionKey = BS.ByteString

type Plain = BS.ByteString

type Encrypted = BS.ByteString

data Error =
      -- package 'exp' was expected, but 'act' was received
      UnexpectedPackage { _exp :: Char, _act :: Char }

      -- exception from operation on handle
    | HandleException { _exc :: SomeException }

      -- error while decoding binary
    | DecodeError { _msg :: String }

      -- error from underlying crypto module
    | CryptoError { _cause :: String }

mapException :: IO a -> ExceptT Error IO a
mapException = withExceptT HandleException . ExceptT . try

mapLeft :: (e -> Error) -> Either e a -> Either Error a
mapLeft f (Left v)  = Left (f v)
mapLeft _ (Right v) = Right v
