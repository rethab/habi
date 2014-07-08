module Types where

import Control.Exception (SomeException)
import qualified Data.ByteString as BS

-- fingerprint
type Fpr = BS.ByteString

type SessionKey = BS.ByteString

data Error =
      -- package 'exp' was expected, but 'act' was received
      UnexpectedPackage { _exp :: Char, _act :: Char }

      -- exception from operation on handle
    | HandleException { _exc :: SomeException }

      -- error while decoding binary
    | DecodeError { _msg :: String }
