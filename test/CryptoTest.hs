{-# LANGUAGE OverloadedStrings #-}
module CryptoTest (tests) where

import Control.Monad.Trans.Reader
import Control.Monad.Trans.Except
import Data.Word (Word8)
import Test.Framework.Providers.QuickCheck2
import Test.Framework.Providers.HUnit
import Test.QuickCheck
import Test.HUnit hiding (assert)
import Test.QuickCheck.Monadic
import TestUtil

import qualified Data.ByteString     as BS

import Habi.Crypto
import Habi.Types
                      
tests = [
          -- padding
          testProperty "pad_unpad_reverse" pad_unpad_reverse 
        , testProperty "padded_lenght_mod_len" padded_lenght_mod_len
        , testProperty "padded_lenght_longer" padded_lenght_longer
        , testCase     "unpad_empty" unpad_empty
        , testCase     "already_correct_len" already_correct_len

          -- symmetric encryption
        , testProperty "sym_encr_inverse" sym_encr_inverse
        , testProperty "sym_encr_inverse_iv_add" sym_encr_inverse_iv_add
        , testCase     "sym_encr_wrong_keylen" sym_encr_wrong_keylen
        , testCase     "sym_decr_wrong_keylen" sym_decr_wrong_keylen
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

unpad_empty :: Assertion
unpad_empty =
    assertEqual "fault tolerance" BS.empty (unpad BS.empty)

already_correct_len :: Assertion
already_correct_len =
    assertEqual "already_correct_len" padded (pad 32 toPad)
 where toPad = BS.replicate 32 32 
       padded = BS.replicate 64 32

sym_encr_inverse :: BS.ByteString -> Property
sym_encr_inverse bs = monadicIO go
    where go = do Right r <- run act
                  assert $ r == bs

          act = do sessKey <- randomSessionKey
                   Right enc <- symmetricEncrypt sessKey newIV bs
                   symmetricDecrypt sessKey newIV enc

sym_encr_inverse_iv_add :: Word8 -> BS.ByteString -> Property
sym_encr_inverse_iv_add n bs = monadicIO go
    where go = do Right r <- run act
                  assert $ r == bs

          act = do sessKey <- randomSessionKey
                   let iv = iterate incrementIV newIV !! (fromIntegral n)
                   Right enc <- symmetricEncrypt sessKey iv bs
                   symmetricDecrypt sessKey iv enc

sym_encr_wrong_keylen :: Assertion
sym_encr_wrong_keylen =
    do res <- runT $ symEnc "key" newIV "plain" 
       assertBool "should fail" (isLeft res)
       let err = fromLeft res
       let expected = CryptoError undefined
       assertBool "should be CryptoError" (err ~=~ expected)

sym_decr_wrong_keylen :: Assertion
sym_decr_wrong_keylen =
    do res <- runT $ symDecr "key" newIV "plain" 
       assertBool "should fail" (isLeft res)
       let err = fromLeft res
       let expected = CryptoError undefined
       assertBool "should be CryptoError" (err ~=~ expected)

runT :: ExceptT Error (ReaderT CryptoCtx IO) a -> IO (Either Error a)
runT act = runReaderT (runExceptT act) undefined
