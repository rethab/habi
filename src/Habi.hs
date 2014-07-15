module Habi (

    -- * Handshake
      leecherHandshake
    , seederHandshake

    -- * Symmetric Encryption
    , Crypto.symmetricDecrypt
    , Crypto.symmetricEncrypt

    -- * Initialization Vector
    , Crypto.incrementIV
    , Crypto.newIV
    , Crypto.randomSessionKey

    -- * Types
    , Encrypted
    , Plain
    , SessionKey
    , IV

) where

import Control.Monad.Trans.Reader (ReaderT, runReaderT)
import Control.Monad.Trans.Except (ExceptT, runExceptT)
import Network.Socket             (Socket, socketToHandle)
import System.IO                  (Handle, IOMode(ReadWriteMode))

import qualified Habi.Handshake as Intern
import qualified Habi.Crypto as Crypto
import Habi.Types

-- | path pointing to the gpg homedir
type GpgHomedir = String

leecherHandshake :: Socket -> GpgHomedir -> Fpr -> IO (Either Error SessionKey)
leecherHandshake s hd fpr = s2h s >>= \h -> run hd $ Intern.leecherHandshake fpr h

seederHandshake :: Socket -> GpgHomedir -> Fpr -> IO (Either Error SessionKey)
seederHandshake s hd fpr = s2h s >>= \h -> run hd $ Intern.seederHandshake fpr h

s2h :: Socket -> IO Handle
s2h s = socketToHandle s ReadWriteMode


run :: GpgHomedir -> (ExceptT Error (ReaderT CryptoCtx IO) SessionKey)
        -> IO (Either Error SessionKey)
run homedir act = runReaderT (runExceptT act) (CryptoCtx homedir)
