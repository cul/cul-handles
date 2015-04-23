module Cul
  module Handles
    class DeleteValueRequest < HandleValueRequest
      def initialize(handle)
        super(handle)
        @opCode = asBytes(Hdl::OC_REMOVE_VALUE)
      end
      def addAdminValue(adminHandle, permissions, index)
        if (index.eql?(100))
          raise "Deleting the admin value would leave the handle without an administrator; Use modify value instead."
        end
        super(adminHandle, permissions, index)
      end
    end
    class RemoveValueRequest < BaseRequest
      include Hdl
      def initialize(handle)
        super()
        @opCode = asBytes(OC_REMOVE_VALUE)
        self.responseCode = 0
        @handle = toProtocolString(handle)
        @values = []
      end
    end
  end
end