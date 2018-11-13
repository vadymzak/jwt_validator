require_relative 'base_service'
Dir[File.dirname(__FILE__) + '/algorithms/**/*.rb'].each { |file| require file }
module JwtValidatior
  class Validator < BaseService
    def initialize(payload, algorithm:, algorithm_params:)
      @payload = payload
      @algorithm = algorithm
      @algorithm_params = algorithm_params
    end

    def call
      algorithm_class.call(@payload, @algorithm_params)
    end

    private

    def algorithm_class
      Object.const_get("JwtValidatior::Algorithms::#{@algorithm.capitalize}")
    rescue NameError
      raise JwtValidatior::Exceptions::InvalidAlgorithm, "invalid algorithm #{@algorithm.capitalize}"
    end
  end
end
