require_relative 'exceptions'
module JwtValidatior
  class BaseService
    def self.call(*args)
      new(*args).call
    end
  end
end
