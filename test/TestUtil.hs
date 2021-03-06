{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE FlexibleInstances #-}
module TestUtil where

import Control.Monad.Trans (lift)
import Control.Monad.Trans.State (State, state, modify)
import Data.Word (Word8)
import Test.QuickCheck

import Habi.Crypto
import Habi.Types

import qualified Crypto.Cipher  as C
import qualified Data.ByteString as BS

instance Arbitrary BS.ByteString where
    arbitrary = fmap BS.pack arbitrary

between :: (Ord a) => a -> (a, a) -> Bool
between x (b, t) = x <= t && x >= b

alice_pub_fpr :: BS.ByteString
alice_pub_fpr = "EAACEB8A"

bob_pub_fpr :: BS.ByteString
bob_pub_fpr = "6C4FB8F2"

data MockState = MockState {

      -- clients may read from this end. this
      -- may be prefilled in a test
      readEnd :: BS.ByteString

      -- clients will write to this end
    , writeEnd :: BS.ByteString
}

newMock :: BS.ByteString -> MockState
newMock bs = MockState bs BS.empty

instance SocketMonad (State MockState) where

    smPut _ bs = lift . modify $ \(MockState r w) ->
        MockState r (w `BS.append` bs)

    smGet _ n = lift . state $ \(MockState r w) ->
        let (h, t) = BS.splitAt n r
        in (h, MockState t w)

instance CryptoMonad (State MockState) where
    asymEncr _  = lift . return . mock_encr_async
    asymDecr    = lift . return . mock_decr_async
    symEnc _ _  = lift . return . mock_encr_sync
    symDecr _ _ = lift . return . mock_decr_sync
    genSessKey  = error "genSessKey"
    genIV       = lift . return $ IV C.nullIV

-- for testing, all encryption/decryption function just map to
-- the successor or predecesor respectively
mock_encr_async, mock_decr_async :: BS.ByteString -> BS.ByteString
mock_encr_sync, mock_decr_sync :: BS.ByteString -> BS.ByteString
mock_encr_async = BS.map safeSucc
mock_decr_async = BS.map safePred
mock_encr_sync  = BS.map (safeSucc . safeSucc) . pad 32
mock_decr_sync  = unpad . BS.map (safePred . safePred)

safeSucc :: Word8 -> Word8
safeSucc n | n < 255   = succ n
           | otherwise = 0

safePred :: Word8 -> Word8
safePred n | n > 0     = pred n
           | otherwise = 255

isLeft :: Either e a -> Bool
isLeft (Left _) = True
isLeft _        = False

fromLeft :: Either e a -> e
fromLeft (Left e) = e
fromLeft _        = error "is not left"

-- fuzzy equals that compares value constructor
(~=~) :: Error -> Error -> Bool
(~=~) (UnexpectedPackage _ _ ) (UnexpectedPackage _ _) = True
(~=~) (SocketException _ ) (SocketException _)         = True
(~=~) (DecodeError _) (DecodeError _)                  = True
(~=~) (CryptoError _) (CryptoError _)                  = True
(~=~) (OtherError _) (OtherError _)                    = True
(~=~) _ _                                              = False
