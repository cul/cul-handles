module Cul
  module Handles
    class CreateHandleRequest < HandleValueRequest
      def initialize(handle)
        super(handle)
        @opCode = asBytes(Hdl::OC_CREATE_HANDLE)
      end
      def valid?
        if not @handle
          return false
        end
        @values.each { |value|
          if value.type == "HS_ADMIN"
            return true
          end
        }
        return false
      end
    end
  end
end
  