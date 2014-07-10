module CryptoTest (tests) where

import Data.Word (Word8)
import Test.Framework.Providers.QuickCheck2
import Test.QuickCheck
import TestUtil ()

import qualified Data.ByteString     as BS

import Crypto
                      
tests = [ testProperty "pad_unpad_reverse" pad_unpad_reverse 
        , testProperty "padded_lenght_mod_len" padded_lenght_mod_len
        , testProperty "padded_lenght_longer" padded_lenght_longer
        ]

pad_guard :: Word8 -> BS.ByteString -> Bool
pad_guard len bytes = len > 0 && not (BS.null bytes)

pad_unpad_reverse :: Word8 -> BS.ByteString -> Property
pad_unpad_reverse len bytes = pad_guard len bytes ==>
    unpad (pad len bytes) == bytes

padded_lenght_mod_len :: Word8 -> BS.ByteString -> Property
padded_lenght_mod_len len bytes = pad_guard len bytes ==>
    pad_len `mod` len == 0
  where pad_len = fromIntegral (BS.length $ pad len bytes)

-- must do padding in any case. assume input bytes
-- already have a structure that could be unpadded
-- with the algorithm and the length is already a
-- multiple of 'len'. if no padding was done, unpadding
-- would result in a different sequence of bytes
padded_lenght_longer :: Word8 -> BS.ByteString -> Property
padded_lenght_longer len bytes = pad_guard len bytes ==>
    pad_len > BS.length bytes
  where pad_len = fromIntegral (BS.length $ pad len bytes)
