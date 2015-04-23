module Cul
  module Handles
     class HandleValue
      include Hdl
      PERM_ADMIN_READ = 0x8
      PERM_ADMIN_WRITE = 0x4
      PERM_PUBLIC_READ = 0x2
      PERM_PUBLIC_WRITE = 0x1
      TTL_TYPE_RELATIVE = 0
      TTL_TYPE_ABSOLUTE = 1
      MAX_RECOGNIZED_TTL = 86400*2 # 2 days
      def initialize(data=[],handle="")
        super()
        @handle=handle
        @refs = []
        @data = []
        @type = []
        @perm = 14 # admin r/w; public r
        @ttlType = TTL_TYPE_RELATIVE # default
        @ttl = asBytes(86400) # default is 86400 seconds = 1440 minutes = 24 hours
        @timestamp = asBytes(Time.new().to_i) # number of seconds since computing era
        deserialize(data) unless data.length == 0
      end
      def deserialize(data)
        @index = data[0..3]
        @timestamp = data[4..7]
        @ttlType = data[8]
        @ttl = data[9..12]
        @perm = data[13]
        typeLen = fromBytes(data[14..17])
        offset = 18
        @type = data[18...18+typeLen]
        offset = offset + typeLen
        dataLen = fromBytes(data[offset...offset+4])
        offset = offset + 4
        @data = data[offset...offset+dataLen]
        offset = offset + dataLen
        refsLen = fromBytes(data[offset...offset+4])
        offset = offset + 4
        @refs = []    
        (1..refsLen).each{
          @refs.push(fromBytes(data[offset...offset+4]))
          offset = offset + 4  
        }
      end
      def serialize()
        result = [].concat(@index)
        result.concat(@timestamp)
        result.concat([@ttlType])
        result.concat(@ttl)
        result.concat([@perm])
        result.concat(asBytes(@type.length))
        result.concat(@type)
        result.concat(asBytes(@data.length))
        result.concat(@data)
        result.concat(asBytes(@refs.length))
        if(@refs.length > 0)
          @refs.each{ | ref|
            result.concat(asBytes(ref))
          }
        end
        return result
      end
      def handle
        @handle
      end
      def index=(val)
        @index= val
      end
      def index
        fromBytes(@index)
      end  
      def timestamp=(val)
        @timestamp=val
      end
      def ttlType=(val)
        @ttlType = val
      end
      def ttl=(val)
        @ttl = val
      end
      def perm=(val)
        @perm = val
      end
      def adminRead
        @perm & PERM_ADMIN_READ
      end
      def adminWrite
        @perm & PERM_ADMIN_WRITE
      end
      def publicRead
        @perm & PERM_PUBLIC_READ
      end
      def publicWrite
        @perm & PERM_PUBLIC_WRITE
      end
      def type=(val)
        @type=val
      end
      def type
        return @type.pack('U*')
      end
      def data=(val)
        @data=val
      end
      def data
        @data.pack('U*')
      end  
      def refs=(val)
        @refs = val  
      end
      def to_s
        if (type == "HS_ADMIN")
          return "admin handle data: ttl= " + fromBytes(@ttl).to_s + " ; ttlType= " + @ttlType.to_s + "; index = " + index.to_s +  "; " + decodeAdminData(@data).to_s + "; permissions = " + @perm.to_s
        end
        return "type: " + type + "; index=" + index.to_s + "; data.length: " + @data.length.to_s + " ; data: " + data + "; data(hex): " + @data.collect { |element| "%02x" % element }.join+ "; permissions = " + @perm.to_s
      end
    end    
  end
end