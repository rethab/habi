{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE FlexibleInstances #-}
module TestUtil where

import Control.Monad.Trans (lift)
import Control.Monad.Trans.State (State, state, modify)
import Data.Word (Word8)
import Test.QuickCheck

import Handshake
import Crypto

import qualified Data.ByteString as BS

instance Arbitrary BS.ByteString where
    arbitrary = fmap BS.pack arbitrary

between :: Int -> (Int, Int) -> Bool
between x (b, t) = x <= t && x >= b

data MockState = MockState {

      -- clients may read from this end. this
      -- may be prefilled in a test
      readEnd :: BS.ByteString

      -- clients will write to this end
    , writeEnd :: BS.ByteString
}

newMock :: BS.ByteString -> MockState
newMock bs = MockState bs BS.empty

instance HandleMonad (State MockState) where

    hmPut _ bs = lift . modify $ \(MockState r w) ->
        MockState r (w `BS.append` bs)

    hmGet _ n = lift . state $ \(MockState r w) ->
        let (h, t) = BS.splitAt n r
        in (h, MockState t w)

instance CryptoMonad (State MockState) where
    asymFor _  = lift . return . mock_encr_async
    asymDecr   = lift . return . mock_decr_async
    symEnc _   = lift . return . mock_encr_sync
    symDecr _  = lift . return . mock_decr_sync
    genSessKey = undefined

mock_encr_async = BS.map safeSucc
mock_decr_async = BS.map safePred
mock_encr_sync  = BS.map (safeSucc . safeSucc)
mock_decr_sync  = BS.map (safePred . safePred)

safeSucc :: Word8 -> Word8
safeSucc n | n < 255   = succ n
           | otherwise = 0

safePred :: Word8 -> Word8
safePred n | n > 0     = pred n
           | otherwise = 255
