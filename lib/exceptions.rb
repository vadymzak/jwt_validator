module JwtValidatior
  module Exceptions
    class BaseException < RuntimeError; end
    class InvalidAlgorithm < BaseException; end
    class ExpiredToken < BaseException; end
    class IvalidToken < BaseException; end
  end
end
