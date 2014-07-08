module Crypto where

import Control.Monad.Trans (lift)
import Control.Monad.Trans.Except

import qualified Data.ByteString as BS

import Types

type Plain = BS.ByteString
type Encrypted = BS.ByteString

class (Monad m) => CryptoMonad m where
    asymFor  :: Fpr -> Plain -> ExceptT Error m Encrypted
    asymDecr :: Encrypted -> ExceptT Error m Plain
    symEnc   :: SessionKey -> Plain -> ExceptT Error m Encrypted
    symDecr  :: SessionKey -> Encrypted -> ExceptT Error m Plain
