module Cul
  module Handles
    class DeleteHandleRequest < BaseRequest
      include Hdl
      def initialize(handle)
        super()
        @opCode = asBytes(Hdl::OC_DELETE_HANDLE)
        self.responseCode = 0
        @handle = toProtocolString(handle)
      end
      def valid?
        if not @handle
          return false
        end
        return true
      end
      def encodeBody
        @body = @handle
      end
    end
  end
end