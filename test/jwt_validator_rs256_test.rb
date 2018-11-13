require 'minitest/autorun'
require 'jwt'
require_relative '../lib/jwt_validator'

class JwtValidatiorTest < Minitest::Test
  def setup
    #@hmac_secret = 'hmac_secret'.freeze
    @rsa_private = 'rsa_private'.freeze
    @rsa_public = 'rsa_private'.freeze
    @hmac_alghorythm = 'RS256'.freeze
    @valid_payload = {
      'user_id' => 1,
      'exp' => Time.now.to_i + 4 * 3600
    }.freeze
    @valid_token = JWT.encode(@valid_payload, @rsa_private, @hmac_alghorythm)
  end

  def test_raises_exception_with_ivalid_algorithm
    assert_raises JwtValidatior::Exceptions::InvalidAlgorithm do
      JwtValidatior::Validator.call(@valid_token, algorithm: :invalid, algorithm_params: {})
    end
  end

  def test_valid_token_with_hmac_raise_no_error
    result = JwtValidatior::Validator.call(@valid_token,
                                           algorithm: :rs256,
                                           algorithm_params: { secret: @rsa_public, alg: @hmac_alghorythm })
    assert_equal @valid_payload, result
  end

  def test_expired_token_raises_exception
    payload = {
      'user_id' => 1,
      'exp' => Time.now.to_i - 4 * 3600
    }
    token = JWT.encode(payload, @hmac_secret, @hmac_alghorythm)
    assert_raises JwtValidatior::Exceptions::ExpiredToken do
      JwtValidatior::Validator.call(token,
                                    algorithm: :hmac,
                                    algorithm_params: { secret: @hmac_secret, alg: @hmac_alghorythm })
    end
  end

  def test_invalid_hash_alg_raises_exception
    assert_raises JwtValidatior::Exceptions::InvalidAlgorithm do
      JwtValidatior::Validator.call(@valid_token,
                                    algorithm: :invalid,
                                    algorithm_params: { secret: @hmac_secret, alg: @hmac_alghorythm })
    end
  end

  def test_invalid_secret_key_raises_exception
    assert_raises JwtValidatior::Exceptions::IvalidToken do
      JwtValidatior::Validator.call(@valid_token,
                                    algorithm: :hmac,
                                    algorithm_params: { secret: "#{@hmac_secret}123", alg: @hmac_alghorythm })
    end
  end

  def test_missing_alg_key_raises_exception
    assert_raises JwtValidatior::Hmac::Exceptions::MissingRequiredKey do
      JwtValidatior::Validator.call(@valid_token,
                                    algorithm: :hmac,
                                    algorithm_params: { secret: @hmac_secret })
    end
  end

  def test_invalid_alg_key_raises_exception
    assert_raises JwtValidatior::Hmac::Exceptions::InvalidHmacAlgorithm do
      JwtValidatior::Validator.call(@valid_token,
                                    algorithm: :hmac,
                                    algorithm_params: { secret: @hmac_secret, alg: :invalid })
    end
  end
end
