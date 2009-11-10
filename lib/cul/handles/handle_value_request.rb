module Cul
  module Handles
    class HandleValueRequest < BaseRequest
      ADMIN_ONLY = HandleValue::PERM_ADMIN_READ & HandleValue::PERM_ADMIN_WRITE
      def initialize(handle)
        super()
        self.responseCode = 0
        self.certify=true
        self.authoritative=true
        self.returnRequestDigest=(true)
        @handle = toProtocolString(handle)
        @values = []
      end
      def addURLValue(urlValue)
        # serialize handle value
        value = HandleValue.new()
        value.data = urlValue.unpack('U*')
        value.type = "URL".unpack('U*')
        value.index = asBytes(1) # is this a default?
        @values.push(value)
      end
      def addAdminValue(adminHandle, permissions, index=INDEX_ADMIN_HANDLE)
        value = HandleValue.new()
        value.data=value.encodeAdminData(adminHandle, permissions, INDEX_AUTH)
        value.type = "HS_ADMIN".unpack('U*')
        value.index = asBytes(index) # is this a default?
        @values.push(value)
      end
      def addSecretKeyValue(secret)
        value = HandleValue.new()
        value.data=secret.unpack('U*')

        value.type="HS_SECKEY".unpack('U*')
        value.perm=(ADMIN_ONLY)
        value.index = asBytes(INDEX_AUTH)
        @values.push(value)
      end
      def encodeBody
        result = [].concat(@handle)
        result.concat(asBytes(@values.length))
        @values.each {|value|
          #puts value.serialize.join unless value.nil?
          result.concat(value.serialize)
        }
        @body = result
      end
    end
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
    class AddValueRequest < HandleValueRequest
      def initialize(handle)
        super(handle)
        @opCode = asBytes(Hdl::OC_ADD_VALUE)
      end
    end
    class ModifyValueRequest < HandleValueRequest
      def initialize(handle)
        super(handle)
        @opCode = asBytes(Hdl::OC_MODIFY_VALUE)
      end
    end
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
  end
end