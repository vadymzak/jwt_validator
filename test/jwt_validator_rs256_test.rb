require 'minitest/autorun'
require 'jwt'
require_relative '../lib/jwt_validator'

class JwtValidatiorTest < Minitest::Test
  def setup
    @rsa_private = OpenSSL::PKey::RSA.generate 2048.freeze
    @rsa_public = @rsa_private.public_key.freeze
    @alghorythm = 'RS256'.freeze
    @valid_payload = {
      'user_id' => 1,
      'exp' => Time.now.to_i + 4 * 3600
    }.freeze
    @valid_token = JWT.encode(@valid_payload, @rsa_private, @alghorythm)
  end

  def test_raises_exception_with_ivalid_algorithm
    assert_raises JwtValidatior::Exceptions::InvalidAlgorithm do
      JwtValidatior::Validator.call(@valid_token, algorithm: :invalid, algorithm_params: {})
    end
  end

  def test_valid_token_with_rs256_raise_no_error
    result = JwtValidatior::Validator.call(@valid_token,
                                           algorithm: :rs256,
                                           algorithm_params: { secret: @rsa_public, alg: @alghorythm })
    assert_equal @valid_payload, result
  end

  def test_expired_token_raises_exception
    payload = {
      'user_id' => 1,
      'exp' => Time.now.to_i - 4 * 3600
    }
    token = JWT.encode(payload, @rsa_private, @alghorythm)
    assert_raises JwtValidatior::Exceptions::ExpiredToken do
      JwtValidatior::Validator.call(token,
                                    algorithm: :rs256,
                                    algorithm_params: { secret: @rsa_public, alg: @alghorythm })
    end
  end

  def test_invalid_hash_alg_raises_exception
    assert_raises JwtValidatior::Exceptions::InvalidAlgorithm do

      JwtValidatior::Validator.call(@valid_token,
                                    algorithm: :invalid,
                                    algorithm_params: { secret: @rsa_public, alg: @alghorythm })
    end
  end

  def test_invalid_secret_key_raises_exception
    invalid_key = OpenSSL::PKey::RSA.generate 2048
    assert_raises JwtValidatior::Exceptions::IvalidToken do
      JwtValidatior::Validator.call(@valid_token,
                                    algorithm: :rs256,
                                    algorithm_params: { secret: invalid_key, alg: @alghorythm })
    end
  end

  def test_missing_alg_key_raises_exception
    assert_raises JwtValidatior::Algorithms::Rs256::Exceptions::MissingRequiredKey do
      JwtValidatior::Validator.call(@valid_token,
                                    algorithm: :rs256,
                                    algorithm_params: { secret: @rsa_public })
    end
  end

  def test_invalid_alg_key_raises_exception
    assert_raises JwtValidatior::Algorithms::Rs256::Exceptions::InvalidRs256Algorithm do
      JwtValidatior::Validator.call(@valid_token,
                                    algorithm: :rs256,
                                    algorithm_params: { secret: @rsa_public, alg: :invalid })
    end
  end
end
