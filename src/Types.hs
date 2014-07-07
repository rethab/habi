module Types where

import Control.Exception (SomeException)
import qualified Data.ByteString as BS

-- fingerprint
type Fpr = BS.ByteString

type SessionKey = BS.ByteString

data Error =
      -- package 'exp' was expected, but 'act' was received
      UnexpectedPackage { exp :: Char, act :: Char }

      -- exception from operation on handle
    | HandleException { exc :: SomeException }

      -- error while decoding binary
    | DecodeError { msg :: String }