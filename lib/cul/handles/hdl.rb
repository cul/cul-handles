module Cul
  module Handles
    module Hdl
      # OpFlag masks
      MSG_FLAG_AUTH = 0x80 # don't use cache, use only primaries
      MSG_FLAG_CERT = 0x40 # asks server to sign responses
      MSG_FLAG_ENCR = 0x20 # asks server to encrypt responses
      MSG_FLAG_RECU = 0x10 # server should try and resolve handle if not found
      MSG_FLAG_CACR = 0x08 # responses should be signed by cache
      MSG_FLAG_CONT = 0x04 # there are more parts to this message
      MSG_FLAG_KPAL = 0x02 # keep the socket open for more requests
      MSG_FLAG_PUBL = 0x01 # resolution requests should only return public vals
      MSG_FLAG_RRDG = 0x80 # responses should include a digest of the request
      MSG_FLAG_AUTH_INDEX = 0
      MSG_FLAG_CERT_INDEX = 0
      MSG_FLAG_ENCR_INDEX = 0
      MSG_FLAG_RECU_INDEX = 0
      MSG_FLAG_CACR_INDEX = 0
      MSG_FLAG_CONT_INDEX = 0
      MSG_FLAG_KPAL_INDEX = 0
      MSG_FLAG_PUBL_INDEX = 0
      MSG_FLAG_RRDG_INDEX = 1
      # MessageFlag masks
      ENV_FLAG_COMPRESSED = 0x80
      ENV_FLAG_ENCRYPTED = 0x40
      ENV_FLAG_TRUNCATED = 0x20
      # OpCode values
      OC_RESERVED = 0
      OC_RESOLUTION = 1
      OC_GET_SITEINFO = 2
      OC_CREATE_HANDLE = 100
      OC_DELETE_HANDLE = 101
      OC_ADD_VALUE = 102
      OC_REMOVE_VALUE = 103
      OC_MODIFY_VALUE = 104
      OC_LIST_HANDLE = 105
      OC_LIST_NA = 106
      OC_CHALLENGE_RESPONSE = 200
      OC_VERIFY_RESPONSE = 201
      OC_SESSION_SETUP = 400
      OC_SESSION_TERMINATE = 401
      OC_SESSION_EXCHANGEKEY = 402
      # ResponseCode values
      RC_RESERVED = 0
      RC_SUCCESS = 1
      RC_ERROR = 2
      RC_SERVER_BUSY = 3
      RC_PROTOCOL_ERROR = 4
      RC_OPERATION_DENIED = 5
      RC_RECUR_LIMIT_EXCEEDED = 6
      RC_HANDLE_NOT_FOUND = 100
      RC_HANDLE_ALREADY_EXIST = 101
      RC_INVALID_HANDLE = 102
      RC_VALUE_NOT_FOUND = 200
      RC_VALUE_ALREADY_EXIST = 201
      RC_VALUE_INVALID = 202
      RC_EXPIRED_SITE_INFO = 300
      RC_SERVER_NOT_RESP = 301
      RC_SERVICE_REFERRAL = 302
      RC_NA_DELEGATE = 303
      RC_NOT_AUTHORIZED = 400
      RC_ACCESS_DENIED = 401
      RC_AUTHEN_NEEDED = 402
      RC_AUTHEN_FAILED = 403
      RC_INVALID_CREDENTIAL = 404
      RC_AUTHEN_TIMEOUT = 405
      RC_UNABLE_TO_AUTHEN = 406
      RC_SESSION_TIMEOUT = 500
      RC_SESSION_FAILED = 501
      RC_NO_SESSION_KEY = 502
      RC_SESSION_NO_SUPPORT = 503
      RC_SESSION_KEY_INVALID = 504
      RC_TRYING = 900
      RC_FORWARDED = 901
      RC_QUEUED = 902
    # handle value admin permissions
      PERM_ADD_HANDLE = 0x0001;
      PERM_DELETE_HANDLE = 0x0002;
      PERM_ADD_NA = 0x0004;
      PERM_DELETE_NA = 0x0008;
      PERM_MODIFY_VALUE = 0x0010;
      PERM_REMOVE_VALUE = 0x0020;
      PERM_ADD_VALUE = 0x0040;
      PERM_MODIFY_ADMIN = 0x0080;
      PERM_REMOVE_ADMIN = 0x0100;
      PERM_ADD_ADMIN = 0x0200;
      PERM_READ_VALUE = 0x0400;
      PERM_LIST_HDLS = 0x0800;
      PERM_ALL = 0x0fff;
    # standard handle indices
      INDEX_ADMIN_HANDLE = 100 # index for create/delete/super admin
      INDEX_MAINTAINER_HANDLE = 101 # index for modify/update admin
      INDEX_AUTH = 300 # index of HS_SECKEY value
      class UnsignedInt
        def UnsignedInt.asBytes(val)
          [(val&0xff000000)>>24, (val&0xff0000)>>16, (val&0xff00)>>8, val&0xff]
        end
        def UnsignedInt.fromBytes(data)
          result = data[-1]
          for i in ((data.length-1)..1)
            result |= (data[i] << (8*i))
          end
          return result
        end
      end  
    class UnsignedShort
      def UnsignedShort.asBytes(val)
        [(val&0xff00)>>8, val&0xff]
      end
      def UnsignedShort.fromBytes(data)
        result = data[-1]
        for i in ((data.length-1)..1)
          result |= (data[i] << (8*i))
        end
        return result
      end
    end  
    class UnsignedByte
      def UnsignedByte.asBytes(val)
        [val&0xff]
      end
      def UnsignedByte.fromBytes(data)
        if data.to_i == data
          mask = data
        else
          mask = data[0]
        end 
        result = 0
        if mask & 0x01 == 0x01
          result = result + 1
        end
        if mask & 0x02 == 0x02
          result = result + 2
        end
        if mask & 0x04 == 0x04
          result = result + 4
        end
        if mask & 0x08 == 0x08
          result = result + 8
        end
        if mask & 0x10 == 0x10
          result = result + 16
        end
        if mask & 0x20 == 0x20
          result = result + 32
        end
        if mask & 0x40 == 0x40
          result = result + 64
        end
        if mask & 0x80 == 0x80
          result = result + 128
        end
        return result
      end
    end  
      def asBytes(val)
        [(val&0xff000000)>>24,(val&0xff0000)>>16,(val&0xff00)>>8,val&0xff]
      end
      def fromBytes(data)
        if(data.nil?)
          return 0
        end
        result = 0
        shift = data.length - 1
        data.each{|byte|
          digit = UnsignedByte.fromBytes(byte)
          result = result + (digit << (8*shift))
          shift = shift - 1
        }
        return result
      end
      def toProtocolString(data)
        dataBytes = data.unpack('U*').pack('U*').unpack('C*')
        length = dataBytes.length
        result = asBytes(length)
        result.concat(dataBytes)
        return result
      end
      def readProtocolString(data,offset=0)
        octetsRead = 4
        length = fromBytes(data[offset...offset+4])
        pstring = ""
        if length > 0
          pstring = data[offset+4...offset+4+length].pack('C*').unpack('U*').pack('U*')
          octetsRead = octetsRead + length
        end
        return [octetsRead,pstring]    
      end
      def readByteArray(data,offset=0)
        bytes = fromBytes(data[offset...offset+4])
        octetsRead = 4 + bytes
        start = offset + 4
        result = data[start...(start+bytes)]
        return [octetsRead,result]
      end
      def readIntArray(data,offset=0)
        ints = fromBytes(data[offset...offset+4])
        octetsRead = 4 + (4*ints)
        start = offset + 4
        result = data[start...(offset+octetsRead)]
        return [octetsRead,result]
      end
      def calculateValueLen(values,offset=0)
        origOffset = offset
        offset = offset + 14 # index - 4 bytes; timestamp - 4 bytes; ttlType - 1 byte; ttl - 4 bytes; permissions - 1 byte
    
        fieldLen =  fromBytes( values[offset...offset+4]) # type field
        offset = offset + 4 + fieldLen

        fieldLen = fromBytes( values[offset...offset+4])      # data field
        offset = offset + 4 + fieldLen

        fieldLen = fromBytes( values[offset...offset+4])      # references (number of)
        offset = offset + 4 + fieldLen

        for  i in (1..fieldLen)          # each reference - hdl length + hdl + index
          refLen = fromBytes( values[offset...offset+4])
          offset = offset + 4 + refLen + 4
        end      
        return offset - origOffset
      end
      def decodeAdminData(data)
        permissions = fromBytes(data[0..1])
        arrayInfo = readByteArray(data[2...-1])
        offset = 2 + arrayInfo[0]
        adminHandle = arrayInfo[1].pack('U*')
        index = fromBytes(data[offset..offset+3])
        return {'permissions' => permissions, 'handle' => adminHandle, 'index' => index}
      end
      def encodeAdminData(adminHandle, permissions, index)
        result = asBytes(permissions)[2..3]
        hbytes = adminHandle.unpack('U*')
        result.concat(asBytes(hbytes.length))
        result.concat(hbytes)
        result.concat(asBytes(index))
        result
      end
      def convert16t8(data)
        # first split into bytes
        []
      end
    end
  end
end